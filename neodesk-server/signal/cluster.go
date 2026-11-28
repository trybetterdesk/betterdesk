package signal

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/cluster"
	pb "github.com/neodeskapp/neodesk/neodesk-server/proto"
	"google.golang.org/protobuf/proto"
)

// Mesh is what signal needs from cluster.Mesh: its own name, calls to
// other pods and answers to theirs.
type Mesh interface {
	Self() string
	Call(ctx context.Context, pod, name string, body []byte) ([]byte, error)
	Handle(name string, h cluster.CallHandler)
}

// clusterLink is how a signal server of a cluster reaches the peers and
// connections other pods hold. Each pod keeps its sockets; what crosses
// pods is a call to the pod that holds the socket (DECISIONS M3, M5):
//
//   - sig:udp:<addr>   which pod a UDP address last sent to (sendUDP)
//   - sig:conn:<addr>  which pod holds an initiator's TCP/WS connection
//   - sig:punch:<addr> which pod holds a P2P-first fallback timer
//   - sig:lan:<key>    which pod waits for a LAN address answer
//   - sig:pend*:...    relay correlation, read by whichever pod gets the
//     target's RelayResponse
//
// Peers themselves are found through the peer map's directory.
type clusterLink struct {
	mesh Mesh
	kv   cluster.KV

	// udpSeen holds when this pod last wrote sig:udp for an address, so
	// a peer's heartbeats refresh the index about once a minute.
	udpSeen sync.Map // addr key -> time.Time
	// udpWrites carries index writes off the UDP read loop.
	udpWrites chan string
}

const (
	// udpIndexTTL: a UDP address belongs to the pod it last sent to for
	// three minutes; refreshed every udpIndexRefresh while it keeps
	// sending (heartbeats come every few seconds).
	udpIndexTTL     = 3 * time.Minute
	udpIndexRefresh = time.Minute
	// connIndexTTL matches the life of a waiting initiator connection
	// (maxTTL in cleanupTCPPunchConns).
	connIndexTTL = 2 * time.Minute
	// pendingIndexTTL matches the life of relay correlation entries.
	pendingIndexTTL = 2 * time.Minute
	// lanIndexTTL matches the 30 s a LAN answer is accepted.
	lanIndexTTL = 30 * time.Second
	// remoteCallTimeout bounds a call to another pod on the session path.
	remoteCallTimeout = 2 * time.Second
)

// SetCluster makes the server reach peers on other pods through mesh and
// share its routing indexes in kv. Without it the server works alone.
func (s *Server) SetCluster(mesh Mesh, kv cluster.KV) {
	if mesh == nil || kv == nil {
		return
	}
	link := &clusterLink{mesh: mesh, kv: kv, udpWrites: make(chan string, 4096)}
	s.cl = link
	mesh.Handle("signal.send-udp", s.serveSendUDP)
	mesh.Handle("signal.send-peer", s.serveSendPeer)
	mesh.Handle("signal.forward-initiator", s.serveForwardInitiator)
	mesh.Handle("signal.cancel-punch", s.serveCancelPunch)
	mesh.Handle("signal.local-addr", s.serveLocalAddr)
	mesh.Handle("signal.peer-moved", s.servePeerMoved)
	// A publish that replaced another pod's entry tells that pod too, for
	// a move faster than that pod's own publish
	s.peers.SetMovedHandler(func(id, from string) {
		if from != mesh.Self() {
			go s.call(from, "signal.peer-moved", remoteMsg{ID: id})
		}
	})
	go link.writeUDPIndex(s)
}

// clustered reports whether other pods may hold peers.
func (s *Server) clustered() bool { return s != nil && s.cl != nil }

type remoteMsg struct {
	Addr   string `json:"addr,omitempty"`
	ID     string `json:"id,omitempty"`
	Key    string `json:"key,omitempty"`
	Msg    []byte `json:"msg,omitempty"`
	Cancel bool   `json:"cancel,omitempty"`
}

// call asks pod to run name with req and reports whether it says it
// delivered. The time the call took is logged, so the cost of crossing
// pods shows in the logs.
func (s *Server) call(pod, name string, req remoteMsg) bool {
	body, err := json.Marshal(req)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(s.baseContext(), remoteCallTimeout)
	defer cancel()
	start := time.Now()
	out, err := s.cl.mesh.Call(ctx, pod, name, body)
	took := time.Since(start)
	if err != nil {
		log.Printf("[signal] cluster: %s on %s failed after %s: %v", name, pod, took.Round(time.Microsecond), err)
		return false
	}
	ok := string(out) == "1"
	log.Printf("[signal] cluster: %s on %s took %s (delivered=%v)", name, pod, took.Round(time.Microsecond), ok)
	return ok
}

func answer(ok bool) []byte {
	if ok {
		return []byte("1")
	}
	return []byte("0")
}

func decodeRemote(body []byte) (remoteMsg, *pb.RendezvousMessage, error) {
	var req remoteMsg
	if err := json.Unmarshal(body, &req); err != nil {
		return req, nil, err
	}
	if len(req.Msg) == 0 {
		return req, nil, nil
	}
	msg := &pb.RendezvousMessage{}
	if err := proto.Unmarshal(req.Msg, msg); err != nil {
		return req, nil, err
	}
	return req, msg, nil
}

func marshalMsg(msg *pb.RendezvousMessage) []byte {
	b, err := proto.Marshal(msg)
	if err != nil {
		return nil
	}
	return b
}

// noteUDPSource records that addr sent to this pod (called for every UDP
// datagram when clustered).
func (s *Server) noteUDPSource(addr *net.UDPAddr) {
	if !s.clustered() || addr == nil {
		return
	}
	key := normalizeAddrKey(addr.String())
	now := time.Now()
	if v, ok := s.cl.udpSeen.Load(key); ok && now.Sub(v.(time.Time)) < udpIndexRefresh {
		return
	}
	s.cl.udpSeen.Store(key, now)
	select {
	case s.cl.udpWrites <- key:
	default: // index writes are best effort; the next datagram tries again
		s.cl.udpSeen.Delete(key)
	}
}

func (l *clusterLink) writeUDPIndex(s *Server) {
	for {
		select {
		case <-s.baseContext().Done():
			return
		case key := <-l.udpWrites:
			if err := l.kv.Set(context.Background(), "sig:udp:"+key, l.mesh.Self(), udpIndexTTL); err != nil {
				l.udpSeen.Delete(key)
			}
		}
	}
}

// pruneUDPSeen drops addresses this pod has not heard from in a while.
func (s *Server) pruneUDPSeen(now time.Time) {
	if !s.clustered() {
		return
	}
	s.cl.udpSeen.Range(func(k, v any) bool {
		if now.Sub(v.(time.Time)) > udpIndexTTL {
			s.cl.udpSeen.Delete(k)
		}
		return true
	})
}

// ownerOf returns the pod named under key in the shared index, "" when
// none or this pod.
func (s *Server) ownerOf(key string) string {
	if !s.clustered() {
		return ""
	}
	pod, ok, err := s.cl.kv.Get(s.baseContext(), key)
	if err != nil || !ok || pod == s.cl.mesh.Self() {
		return ""
	}
	return pod
}

// remoteUDPOwner is the pod that holds addr's UDP flow when it is not this
// one: a reply must leave from the pod the client sent to, or its NAT
// drops it.
func (s *Server) remoteUDPOwner(addr *net.UDPAddr) string {
	if !s.clustered() {
		return ""
	}
	key := normalizeAddrKey(addr.String())
	if v, ok := s.cl.udpSeen.Load(key); ok && time.Since(v.(time.Time)) < udpIndexTTL {
		return ""
	}
	return s.ownerOf("sig:udp:" + key)
}

func (s *Server) serveSendUDP(_ context.Context, _ string, body []byte) ([]byte, error) {
	req, msg, err := decodeRemote(body)
	if err != nil || msg == nil {
		return nil, errors.New("bad send-udp")
	}
	addr, err := net.ResolveUDPAddr("udp", req.Addr)
	if err != nil {
		return nil, err
	}
	return answer(s.sendUDPLocal(msg, addr)), nil
}

func (s *Server) serveSendPeer(_ context.Context, _ string, body []byte) ([]byte, error) {
	req, msg, err := decodeRemote(body)
	if err != nil || msg == nil {
		return nil, errors.New("bad send-peer")
	}
	return answer(s.sendToLocalPeer(req.ID, msg)), nil
}

func (s *Server) serveForwardInitiator(_ context.Context, _ string, body []byte) ([]byte, error) {
	req, msg, err := decodeRemote(body)
	if err != nil || msg == nil {
		return nil, errors.New("bad forward-initiator")
	}
	if req.Cancel {
		s.cancelLocalPunchFallback(req.Key)
	}
	return answer(s.forwardToLocalInitiator(req.Key, msg)), nil
}

func (s *Server) serveCancelPunch(_ context.Context, _ string, body []byte) ([]byte, error) {
	req, _, err := decodeRemote(body)
	if err != nil {
		return nil, err
	}
	return answer(s.cancelLocalPunchFallback(req.Key)), nil
}

func (s *Server) serveLocalAddr(_ context.Context, _ string, body []byte) ([]byte, error) {
	req, msg, err := decodeRemote(body)
	if err != nil || msg == nil || msg.GetLocalAddr() == nil {
		return nil, errors.New("bad local-addr")
	}
	sender, err := net.ResolveUDPAddr("udp", req.Addr)
	if err != nil {
		return nil, err
	}
	s.completeLocalLANAddr(msg.GetLocalAddr(), sender)
	return answer(true), nil
}

// noteConn records that this pod holds the initiator connection of key.
func (s *Server) noteConn(key string) {
	if !s.clustered() || key == "" {
		return
	}
	_ = s.cl.kv.Set(s.baseContext(), "sig:conn:"+key, s.cl.mesh.Self(), connIndexTTL)
}

// notePunch records that this pod holds the fallback timer of key.
func (s *Server) notePunch(key string, ttl time.Duration) {
	if !s.clustered() || key == "" {
		return
	}
	_ = s.cl.kv.Set(s.baseContext(), "sig:punch:"+key, s.cl.mesh.Self(), ttl)
}

// noteLAN records that this pod waits for the LAN answer of key.
func (s *Server) noteLAN(key string) {
	if !s.clustered() || key == "" {
		return
	}
	_ = s.cl.kv.Set(s.baseContext(), "sig:lan:"+key, s.cl.mesh.Self(), lanIndexTTL)
}

// sharedPending is pendingUUID as other pods read it.
type sharedPending struct {
	UUID            string `json:"u,omitempty"`
	TargetID        string `json:"t,omitempty"`
	InitiatorID     string `json:"i,omitempty"`
	CorrelationAddr string `json:"c,omitempty"`
	AdvertisedAddr  string `json:"a,omitempty"`
	CreatedAt       int64  `json:"at"`
	Account         int64  `json:"ac,omitempty"`
	ConsoleSession  string `json:"cs,omitempty"`
}

// sharePending writes the relay correlation entry under its three keys.
func (s *Server) sharePending(key string, p *pendingUUID) {
	if !s.clustered() || p == nil {
		return
	}
	b, err := json.Marshal(sharedPending{
		UUID: p.uuid, TargetID: p.targetID, InitiatorID: p.initiatorID,
		CorrelationAddr: p.correlationAddr, AdvertisedAddr: p.advertisedAddr,
		CreatedAt: p.createdAt.UnixMilli(), Account: p.account, ConsoleSession: p.consoleSession,
	})
	if err != nil {
		return
	}
	ctx := s.baseContext()
	_ = s.cl.kv.Set(ctx, "sig:pend:"+key, string(b), pendingIndexTTL)
	if p.uuid != "" {
		_ = s.cl.kv.Set(ctx, "sig:pendu:"+p.uuid, string(b), pendingIndexTTL)
	}
	if p.advertisedAddr != "" {
		_ = s.cl.kv.Set(ctx, "sig:penda:"+pendingRelayAdvertisedKey(p.targetID, p.advertisedAddr), string(b), pendingIndexTTL)
	}
}

// sharedPendingAt reads a correlation entry another pod wrote.
func (s *Server) sharedPendingAt(key string) *pendingUUID {
	if !s.clustered() {
		return nil
	}
	v, ok, err := s.cl.kv.Get(s.baseContext(), key)
	if err != nil || !ok {
		return nil
	}
	var sp sharedPending
	if json.Unmarshal([]byte(v), &sp) != nil {
		return nil
	}
	return &pendingUUID{
		uuid: sp.UUID, targetID: sp.TargetID, initiatorID: sp.InitiatorID,
		correlationAddr: sp.CorrelationAddr, advertisedAddr: sp.AdvertisedAddr,
		createdAt: time.UnixMilli(sp.CreatedAt), account: sp.Account, consoleSession: sp.ConsoleSession,
	}
}

// remotePeerOwner is the pod that holds peer id when it is another one.
func (s *Server) remotePeerOwner(id string) string {
	if !s.clustered() || s.peers == nil {
		return ""
	}
	if e := s.peers.Get(id); e != nil && e.Owner != "" && e.Owner != s.cl.mesh.Self() {
		return e.Owner
	}
	return ""
}

// notePeerHere tells the pod that held peer id before that it registered
// here now, so that pod drops its stale entry and stops answering for it.
// movedFrom is remotePeerOwner(id) read before the local Put.
func (s *Server) notePeerHere(id, movedFrom string) {
	pod := movedFrom
	if !s.clustered() || id == "" || pod == "" {
		return
	}
	go s.call(pod, "signal.peer-moved", remoteMsg{ID: id})
}

func (s *Server) servePeerMoved(_ context.Context, from string, body []byte) ([]byte, error) {
	req, _, err := decodeRemote(body)
	if err != nil || req.ID == "" {
		return nil, errors.New("bad peer-moved")
	}
	old := s.peers.GetLocal(req.ID)
	dropped := s.peers.DropIfMoved(req.ID)
	if dropped && old != nil && old.UDPAddr != nil {
		// Its address sends to the new pod now
		s.cl.udpSeen.Delete(normalizeAddrKey(old.UDPAddr.String()))
	}
	if dropped {
		log.Printf("[signal] cluster: peer %s moved to %s; dropped here", req.ID, from)
	}
	return answer(dropped), nil
}

package relay

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/neodeskapp/neodesk/neodesk-server/cluster"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
)

// LegMesh is what the relay needs from cluster.Mesh to hand a relay leg to
// another pod.
type LegMesh interface {
	Self() string
	Stream(ctx context.Context, pod, name string, meta map[string]string) (net.Conn, error)
	HandleStream(name string, h cluster.StreamHandler)
}

// meetLink lets the relays of several pods behind one address pair the two
// legs of a session: the first leg to arrive claims the meeting spot of its
// UUID for its pod (relay:meet:<uuid>), and a leg that lands on another pod
// is streamed to that pod, which pairs it as if it had arrived there
// (DECISIONS M2).
type meetLink struct {
	mesh LegMesh
	kv   cluster.KV
	// forwarded counts legs streamed to another pod, for tests and logs.
	forwarded sync.Map // uuid -> pod
}

const (
	// meetTTL: the meeting spot lives as long as a first leg may wait
	// for its partner, plus margin for the partner's own wait.
	meetTTL = config.RelayPairTimeout + 5*time.Second
	// legStream is the cluster stream that carries a forwarded leg.
	legStream = "relay.leg"
)

// SetCluster makes the relay pair legs across the pods of a cluster.
// Without it every leg pairs on the pod it reached.
func (s *Server) SetCluster(mesh LegMesh, kv cluster.KV) {
	if mesh == nil || kv == nil {
		return
	}
	s.meet = &meetLink{mesh: mesh, kv: kv}
	mesh.HandleStream(legStream, s.serveForwardedLeg)
}

// meetingPod returns the pod where the legs of uuid meet when it is
// another one, "" when they meet here. The caller has seen the UUID's
// ticket, so random UUIDs claim no spot.
func (s *Server) meetingPod(uuid string) string {
	if s.meet == nil {
		return ""
	}
	self := s.meet.mesh.Self()
	ctx, cancel := context.WithTimeout(s.baseCtx(), 2*time.Second)
	defer cancel()
	cur, set, err := s.meet.kv.SetNX(ctx, "relay:meet:"+uuid, self, meetTTL)
	if err != nil {
		log.Printf("[relay] Meeting spot of UUID %s unknown (%v); pairing here", relayUUIDLogID(uuid), err)
		return ""
	}
	if set || cur == self {
		return ""
	}
	return cur
}

func (s *Server) baseCtx() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// awaitTicket waits, within the per-IP limits of the authorization wait,
// until uuid has a ticket, without claiming it.
func (s *Server) awaitTicket(uuid, remoteAddr string) bool {
	if s.authorizations == nil || uuid == "" {
		return false
	}
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || ip == "" {
		ip = remoteAddr
	}
	if !s.authWait.acquire(ip) {
		log.Printf("[relay] Relay auth wait rejected from %s (capacity exceeded)", remoteAddr)
		return false
	}
	defer s.authWait.release(ip)
	ctx, cancel := context.WithTimeout(s.baseCtx(), config.RelayAuthWait)
	defer cancel()
	return s.authorizations.WaitForAuthorization(ctx, uuid)
}

// forwardTCPLeg streams a native relay leg to pod and pipes it there. It
// reports false when the stream can't be opened (the pod is gone, and with
// it the first leg).
func (s *Server) forwardTCPLeg(conn net.Conn, uuid, remote, pod string) bool {
	stream, took, err := s.openLeg(uuid, remote, pod)
	if err != nil {
		log.Printf("[relay] Could not hand UUID %s from %s to pod %s after %s: %v", relayUUIDLogID(uuid), remote, pod, took, err)
		return false
	}
	log.Printf("[relay] Leg of UUID %s from %s handed to pod %s (stream opened in %s)", relayUUIDLogID(uuid), remote, pod, took)
	s.meet.forwarded.Store(uuid, pod)
	s.ForwardedLegs.Add(1)
	defer s.ForwardedLegs.Add(-1)
	pipeBoth(s.baseCtx(), conn, stream)
	return true
}

// forwardWSLeg streams a WebSocket relay leg to pod. On the stream each
// WebSocket message travels as one BytesCodec frame, the framing native
// clients use, so the meeting pod pairs it as a native leg: raw copy to a
// native partner, the mixed bridge to a WebSocket one.
func (s *Server) forwardWSLeg(ws *websocket.Conn, uuid, remote, pod string) bool {
	stream, took, err := s.openLeg(uuid, remote, pod)
	if err != nil {
		log.Printf("[relay] Could not hand WS UUID %s from %s to pod %s after %s: %v", relayUUIDLogID(uuid), remote, pod, took, err)
		return false
	}
	log.Printf("[relay] WS leg of UUID %s from %s handed to pod %s (stream opened in %s)", relayUUIDLogID(uuid), remote, pod, took)
	s.meet.forwarded.Store(uuid, pod)
	s.ForwardedLegs.Add(1)
	defer s.ForwardedLegs.Add(-1)
	ws.SetReadLimit(MaxWSRelayMessage)
	idle := config.RelayIdleTimeout
	done := make(chan struct{})
	var once sync.Once
	go func() {
		copyWSToTCPFrames(s.baseCtx(), ws, stream, nil, idle)
		once.Do(func() { close(done) })
	}()
	go func() {
		copyTCPFramesToWS(s.baseCtx(), stream, ws, nil, idle)
		once.Do(func() { close(done) })
	}()
	<-done
	stream.Close()
	_ = ws.Close(websocket.StatusNormalClosure, "")
	return true
}

func (s *Server) openLeg(uuid, remote, pod string) (net.Conn, time.Duration, error) {
	ctx, cancel := context.WithTimeout(s.baseCtx(), 3*time.Second)
	defer cancel()
	start := time.Now()
	stream, err := s.meet.mesh.Stream(ctx, pod, legStream, map[string]string{"uuid": uuid, "remote": remote})
	return stream, time.Since(start).Round(time.Microsecond), err
}

// serveForwardedLeg takes a leg another pod streamed here and pairs it
// like one that arrived on this pod's listener, under the client's own
// address.
func (s *Server) serveForwardedLeg(from string, meta map[string]string, conn net.Conn) {
	uuid, remote := meta["uuid"], meta["remote"]
	if uuid == "" {
		conn.Close()
		return
	}
	if !s.claimRelayUUID(uuid, remote) {
		log.Printf("[relay] Leg of UUID %s from %s via pod %s refused (no ticket)", relayUUIDLogID(uuid), remote, from)
		conn.Close()
		return
	}
	log.Printf("[relay] Leg of UUID %s from %s arrived via pod %s", relayUUIDLogID(uuid), remote, from)
	s.pairIncomingConn(&pendingConn{
		conn:      &addrConn{Conn: conn, remote: remoteAddr(remote)},
		remote:    remote,
		transport: relayTransportTCP,
		created:   timeNow(),
		done:      make(chan struct{}),
	}, uuid)
}

// addrConn is a forwarded leg that reports the client's address, so the
// per-IP session limits count the client and not the pod that forwarded.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func remoteAddr(s string) net.Addr {
	if a, err := net.ResolveTCPAddr("tcp", s); err == nil {
		return a
	}
	return stringAddr(s)
}

// pipeBoth copies both ways until one side ends or ctx ends (the server
// stops), then closes both.
func pipeBoth(ctx context.Context, a, b net.Conn) {
	stop := context.AfterFunc(ctx, func() {
		a.Close()
		b.Close()
	})
	defer stop()
	done := make(chan struct{})
	var once sync.Once
	go func() {
		_, _ = io.Copy(a, b)
		once.Do(func() { close(done) })
	}()
	go func() {
		_, _ = io.Copy(b, a)
		once.Do(func() { close(done) })
	}()
	<-done
	a.Close()
	b.Close()
}

// Drain stops taking new relay connections and waits until the running
// sessions have ended or grace has passed, whichever comes first. Used on
// SIGTERM in a cluster: the load balancer has stopped sending this pod new
// sessions, and running ones get grace to finish before the pod exits.
// It returns the number of sessions still running when it gave up.
func (s *Server) Drain(grace time.Duration) int64 {
	if s.tcpLn != nil {
		_ = s.tcpLn.Close()
	}
	if s.wsHTTP != nil {
		// Close the listener only; hijacked relay sockets live on
		_ = s.wsHTTP.Close()
	}
	deadline := time.Now().Add(grace)
	for {
		// Legs this pod hands to another pod count too: the client's
		// connection to them ends with this pod
		n := s.ActiveSessions.Load() + s.ForwardedLegs.Load()
		if n == 0 {
			return 0
		}
		if !time.Now().Before(deadline) {
			log.Printf("[relay] Grace of %s over with %d session(s) still running", grace, n)
			return n
		}
		time.Sleep(200 * time.Millisecond)
	}
}

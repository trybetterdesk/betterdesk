package signal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/neodeskapp/neodesk/neodesk-server/audit"
	"github.com/neodeskapp/neodesk/neodesk-server/auth"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/crypto"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/events"
	"github.com/neodeskapp/neodesk/neodesk-server/peer"
	pb "github.com/neodeskapp/neodesk/neodesk-server/proto"
	"github.com/neodeskapp/neodesk/neodesk-server/relay"
)

// refuseRelayProtocolMismatch is returned when one peer uses WebSocket Mode
// and the other uses native TCP/UDP — their relay framings are incompatible.
const refuseRelayProtocolMismatch = "Protocol mismatch: WebSocket and native TCP/UDP cannot share a relay session"

// refuseInitiatorNotAuthorized is returned when PunchHole/RequestRelay comes from
// a peer that is not registered (or not enrollment-approved in managed/locked).
const refuseInitiatorNotAuthorized = "Not authorized"

// refuseTargetOffline refuses a relay to a device that is not registered.
// Every refusal value has a reason code for the console's viewer
// (web-ui/src/lib/remote/server-refusals.json).
const refuseTargetOffline = "Target offline"

// panelWebRemoteInitiatorID is the synthetic initiator id logged when PunchHole/
// RequestRelay arrives from the console's web client bridge, on a connection
// that sent the panel proof (Web Remote).
const panelWebRemoteInitiatorID = "panel-web-remote"

// sharedNATInitiatorID is the synthetic initiator used when ALLOW_SHARED_NAT_INITIATOR
// is enabled and multiple live peers share the initiator's public IP.
// It deliberately does not inherit any peer identity and is distinct from
// panel-web-remote so audit logs stay attributable.
const sharedNATInitiatorID = "shared-nat-initiator"

const legacyOutboundInitiatorPrefix = "legacy-controller-"

func legacyOutboundInitiatorID(raddr *net.UDPAddr) string {
	// This identity only binds relay authorization to the exact connection.
	// It is intentionally not a durable peer identity.
	sum := sha256.Sum256([]byte(normalizeAddrKey(raddr.String())))
	return legacyOutboundInitiatorPrefix + hex.EncodeToString(sum[:8])
}

func isLegacyOutboundInitiator(id string) bool {
	return strings.HasPrefix(id, legacyOutboundInitiatorPrefix)
}

// relayTransportMismatch reports whether initiator and target use incompatible
// relay transports (WebSocket Mode vs native TCP/UDP). Signaling may still be
// mixed; this gate only covers the typical case where ConnType reflects the
// client's relay mode. The relay server remains the hard barrier.
func relayTransportMismatch(initiator, target peer.ConnType) bool {
	return (initiator == peer.ConnWS) != (target == peer.ConnWS)
}

// encodePeerSocketAddr returns the address to place in PunchHoleResponse.
// WebSocket-only peers do not have a UDPAddr, but RustDesk requires a
// non-empty socket_addr before it will process the relay fields. Their
// observed WS address is therefore used as a relay-compatibility address;
// it is not expected to be reachable over UDP when relay is forced.
func encodePeerSocketAddr(entry *peer.Entry) []byte {
	if entry == nil {
		return nil
	}
	if entry.UDPAddr != nil {
		return crypto.EncodeAddr(entry.UDPAddr)
	}
	if strings.TrimSpace(entry.IP) == "" {
		return nil
	}

	host, port, err := net.SplitHostPort(strings.TrimSpace(entry.IP))
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}
	return crypto.EncodeAddr(&net.UDPAddr{IP: ip, Port: int(portNumber)})
}

// encodeRelayResponsePeerSocketAddr returns metadata for an initiator-facing
// RelayResponse. WebSocket peers have no reachable UDP endpoint, so preserve
// their trusted IP while suppressing the reverse proxy's ephemeral port.
func encodeRelayResponsePeerSocketAddr(entry *peer.Entry) []byte {
	if entry == nil {
		return nil
	}
	if entry.ConnType != peer.ConnWS {
		return encodePeerSocketAddr(entry)
	}
	if entry.UDPAddr != nil {
		addr := *entry.UDPAddr
		addr.Port = 0
		return crypto.EncodeAddr(&addr)
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(entry.IP))
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return crypto.EncodeAddr(&net.UDPAddr{IP: ip})
}

// relayAdvertisedAddr returns the endpoint that a target RustDesk client will
// see in RequestRelay.socket_addr. Native UDP/TCP clients have a real endpoint
// and keep the existing address unchanged. WebSocket clients do not expose a
// usable UDP source port through the WSS proxy, so advertise the trusted live
// correlation IP with port 0 instead of leaking the proxy's ephemeral TCP
// port or reusing a stale address from the peer registry.
func relayAdvertisedAddr(s *Server, correlationAddr *net.UDPAddr, initiatorID string, initiatorType peer.ConnType) *net.UDPAddr {
	if correlationAddr == nil {
		return nil
	}
	if initiatorType != peer.ConnWS {
		addr := *correlationAddr
		addr.IP = append(net.IP(nil), correlationAddr.IP...)
		return &addr
	}

	addr := &net.UDPAddr{IP: append(net.IP(nil), correlationAddr.IP...)}
	return addr
}

// ensurePunchHoleSocketAddr rejects a success-shaped PunchHoleResponse that
// still has an empty socket_addr. Stock RustDesk only reads Failure when
// socket_addr is empty, and an unset Failure defaults to ID_NOT_EXIST — so a
// peer that is online but lacks an encodable address would otherwise look like
// a missing ID. OFFLINE is the honest signal for "cannot reach this peer".
func ensurePunchHoleSocketAddr(phr *pb.PunchHoleResponse, targetID, relayServer string) *pb.PunchHoleResponse {
	if phr != nil && len(phr.SocketAddr) > 0 {
		return phr
	}
	log.Printf("[signal] PunchHole: empty compatibility socket_addr for target %s — returning OFFLINE instead of unset failure", targetID)
	return &pb.PunchHoleResponse{
		Failure:     pb.PunchHoleResponse_OFFLINE,
		RelayServer: relayServer,
	}
}

// isInboundOnlyDeviceType identifies agents that may be contacted by an
// operator/client but must never start RustDesk P2P or relay sessions
// themselves. Normalize common spelling variants because metadata has existed
// in both underscore and hyphen forms.
func isInboundOnlyDeviceType(deviceType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(deviceType))
	normalized = strings.NewReplacer("-", "", "_", "", " ", "").Replace(normalized)
	return normalized == "osagent" || normalized == "supportagent"
}

func isInboundOnlyPeer(p *db.Peer) bool {
	if p == nil {
		return false
	}
	if isInboundOnlyDeviceType(p.DeviceType) {
		return true
	}
	for _, tag := range strings.FieldsFunc(p.Tags, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if isInboundOnlyDeviceType(tag) {
			return true
		}
	}
	return false
}

// targetAcceptsInboundSession checks durable target status before forwarding a
// new signaling or relay request. The in-memory peer map can remain populated
// briefly after an administrator disables, bans, or deletes a device.
func (s *Server) targetAcceptsInboundSession(targetID string) bool {
	if targetID == "" || s.db == nil {
		return targetID != ""
	}
	p, err := s.db.GetPeer(targetID)
	if err != nil {
		log.Printf("[signal] Target %s database lookup failed: %v", targetID, err)
		return false
	}
	// Keep a pending signal transport alive so approval can take effect
	// immediately, but never allow that transport to receive sessions before
	// the durable managed-enrollment approval exists.
	if s.isPendingEnrollment(targetID) {
		return false
	}
	if p != nil {
		return !p.Banned && !p.Disabled && !p.SoftDeleted
	}
	// Unknown compatibility peers that are not in the pending queue retain the
	// historical behavior.
	state, err := s.db.GetPeerIDState(targetID)
	if err != nil {
		log.Printf("[signal] Target %s state lookup failed: %v", targetID, err)
		return false
	}
	// A target that was never stored by the NeoDesk inventory can still use
	// compatibility signaling in open mode; a known soft-deleted ID cannot.
	return state != db.PeerIDSoftDeleted
}

// isPendingEnrollment reports whether a managed device is waiting for
// operator approval. It is intentionally based on the durable queue rather
// than the in-memory peer map, which can be empty after a restart.
func (s *Server) isPendingEnrollment(peerID string) bool {
	if s == nil || s.db == nil || peerID == "" || s.cfg.EnrollmentMode != config.EnrollmentModeManaged {
		return false
	}
	pending, err := s.db.GetConfig("pending_device_" + peerID)
	return err == nil && pending != ""
}

// pendingEnrollmentIDs returns the ids in the managed approval queue, read
// in one query, or nil when the mode is not managed or no peer in the
// online bitmap states is online.
func (s *Server) pendingEnrollmentIDs(states []byte) map[string]struct{} {
	if s == nil || s.db == nil || s.cfg.EnrollmentMode != config.EnrollmentModeManaged {
		return nil
	}
	anyOnline := false
	for _, b := range states {
		if b != 0 {
			anyOnline = true
			break
		}
	}
	if !anyOnline {
		return nil
	}
	rows, err := s.db.ListConfigByPrefix("pending_device_")
	if err != nil {
		log.Printf("[signal] Pending enrollment lookup failed: %v", err)
		return nil
	}
	ids := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.Value != "" {
			ids[strings.TrimPrefix(row.Key, "pending_device_")] = struct{}{}
		}
	}
	return ids
}

// retainPendingSignalPeer keeps the client's live signal transport while it
// waits for approval. The transport is not usable for sessions until
// targetAcceptsInboundSession sees the approved DB peer row. This removes the
// approval-to-reconnect race without granting pending devices access.
func (s *Server) retainPendingSignalPeer(id, remoteAddr string, udpAddr *net.UDPAddr, serial int32, connType peer.ConnType) *peer.Entry {
	if s == nil || s.peers == nil || id == "" {
		return nil
	}
	now := time.Now()
	entry := &peer.Entry{
		ID:              id,
		IP:              remoteAddr,
		UDPAddr:         udpAddr,
		Serial:          serial,
		ConnType:        connType,
		LastReg:         now,
		FirstSeen:       now,
		HeartbeatCount:  1,
		StatusTier:      peer.StatusOnline,
		LastStatusCheck: now,
	}
	if entry.IP == "" && udpAddr != nil {
		entry.IP = udpAddr.String()
	}
	movedFrom := s.remotePeerOwner(entry.ID)
	s.peers.Put(entry)
	s.notePeerHere(entry.ID, movedFrom)
	return entry
}

// peerPublicKey returns the live peer key and hydrates it from durable storage
// when the peer map was populated before RegisterPk completed (or after a
// signal-server restart). A persisted key is only used when the in-memory
// entry is empty; an active entry can never be replaced by database data.
func (s *Server) peerPublicKey(peerID string, entry *peer.Entry) []byte {
	if entry != nil && len(entry.PK) > 0 {
		return entry.PK
	}
	if s == nil || s.db == nil || peerID == "" {
		return nil
	}

	stored, err := s.db.GetPeer(peerID)
	if err != nil {
		log.Printf("[signal] Failed to load PK for %s from database: %v", peerID, err)
		return nil
	}
	if stored == nil || len(stored.PK) == 0 {
		return nil
	}

	pk := append([]byte(nil), stored.PK...)
	if s.peers != nil && s.peers.SetPKIfEmpty(peerID, pk) {
		log.Printf("[signal] Loaded PK from database for %s (%d bytes)", peerID, len(pk))
	}
	return pk
}

// requiresRelayOnlyCompatibility keeps the temporary RustDesk-compatible
// support-agent path on relay transport. Direct transport has no equivalent
// server-bound session grant yet, so allowing P2P would create an
// authorization bypass around the passive-session policy.
func (s *Server) requiresRelayOnlyCompatibility(peerID string) bool {
	if peerID == "" || s.db == nil {
		return false
	}
	p, err := s.db.GetPeer(peerID)
	if err != nil {
		log.Printf("[signal] Compatibility peer %s lookup failed: %v", peerID, err)
		return true
	}
	return isInboundOnlyPeer(p)
}

// handleUDPMessage dispatches a UDP message to the appropriate handler.
func (s *Server) handleUDPMessage(msg *pb.RendezvousMessage, raddr *net.UDPAddr) {
	switch {
	case msg.GetRegisterPeer() != nil:
		s.handleRegisterPeer(msg.GetRegisterPeer(), raddr)
	case msg.GetRegisterPk() != nil:
		s.handleRegisterPk(msg.GetRegisterPk(), raddr)
	case msg.GetPunchHoleRequest() != nil:
		s.handlePunchHoleRequest(msg.GetPunchHoleRequest(), raddr)
	case msg.GetPunchHoleSent() != nil:
		// Target B tells signal that it's ready — convert to PunchHoleResponse for initiator A
		s.handlePunchHoleSent(msg.GetPunchHoleSent(), raddr, true)
	case msg.GetRequestRelay() != nil:
		s.handleRequestRelay(msg.GetRequestRelay(), raddr)
	case msg.GetFetchLocalAddr() != nil:
		logClientFetchLocalAddr("UDP", raddr.String())
	case msg.GetLocalAddr() != nil:
		s.handleLocalAddr(msg.GetLocalAddr(), raddr)
	case msg.GetHc() != nil:
		// Health check — respond with the same token
		resp := &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_Hc{
				Hc: &pb.HealthCheck{Token: msg.GetHc().Token},
			},
		}
		s.sendUDP(resp, raddr)
	case msg.GetKeyExchange() != nil:
		// Some clients probe signal UDP with KeyExchange; secure handshake is TCP-only.
		log.Printf("[signal] UDP KeyExchange from %s ignored (use TCP signal for secure sessions)", raddr)
	case msg.GetOnlineRequest() != nil:
		resp := s.handleOnlineRequest(msg.GetOnlineRequest())
		if resp != nil {
			s.sendUDP(resp, raddr)
		}
	default:
		log.Printf("[signal] UDP: unhandled message type from %s", raddr)
	}
}

func signalLimiterKey(kind, clientHost, peerID string) string {
	if peerID == "" {
		return fmt.Sprintf("%s:%s", kind, clientHost)
	}
	return fmt.Sprintf("%s:%s:%s", kind, clientHost, peerID)
}

func (s *Server) publishPeerOnline(id string) {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Publish(events.Event{
		Type: events.EventPeerOnline,
		Data: map[string]string{
			"id":     id,
			"status": "online",
		},
	})
}

func (s *Server) allowRegistration(clientHost, peerID string, knownPeer bool) bool {
	// Registered peers send heartbeats every ~12s — rate-limiting those adds
	// lock contention without abuse benefit (peer ID is already validated in memory).
	if knownPeer {
		return true
	}
	if s.limiter == nil {
		return true
	}
	return s.limiter.Allow(signalLimiterKey("reg-new", clientHost, ""))
}

func (s *Server) allowSignalConnection(clientHost string) bool {
	if s.limiter == nil {
		return true
	}
	return s.limiter.Allow(signalLimiterKey("conn", clientHost, ""))
}

// handleMessage dispatches a TCP/WS message. Returns a response or nil.
// For PunchHoleRequest and RequestRelay, we return nil (no immediate response)
// because the signal server holds the TCP connection open and forwards the
// target's response later via tcpPunchConns.
func (s *Server) handleMessage(msg *pb.RendezvousMessage, raddr net.Addr) *pb.RendezvousMessage {
	return s.dispatchMessage(msg, raddr, false)
}

// dispatchMessage is handleMessage for a connection that may be the
// panel's web client: panel is true when the connection's first frame was
// the panel proof (see panel_proof.go).
func (s *Server) dispatchMessage(msg *pb.RendezvousMessage, raddr net.Addr, panel bool) *pb.RendezvousMessage {
	switch {
	case msg.GetRegisterPk() != nil:
		return s.handleRegisterPkTCP(msg.GetRegisterPk(), raddr)
	case msg.GetPunchHoleRequest() != nil:
		// TCP punch hole: forward PunchHole to target via UDP.
		// If target is online, return nil (keep TCP open for later response).
		// If target is offline/not found, return PunchHoleResponse with failure.
		udpAddr, _ := net.ResolveUDPAddr("udp", raddr.String())
		return s.punchHoleRequestTCP(msg.GetPunchHoleRequest(), udpAddr, peer.ConnTCP, panel)
	case msg.GetRequestRelay() != nil:
		// TCP relay request: forward to target via UDP AND send immediate
		// RelayResponse to TCP initiator with signed PK (matching UDP behavior).
		udpAddr, _ := net.ResolveUDPAddr("udp", raddr.String())
		return s.requestRelayTCP(msg.GetRequestRelay(), udpAddr, peer.ConnTCP, panel)
	case msg.GetRelayResponse() != nil:
		// Target sends RelayResponse to be forwarded to the initiator via TCP.
		udpAddr, _ := net.ResolveUDPAddr("udp", raddr.String())
		s.handleRelayResponseForward(msg, udpAddr)
		return nil
	case msg.GetPunchHoleSent() != nil:
		// Target sends PunchHoleSent via TCP — convert to PunchHoleResponse
		// and forward to initiator via their stored TCP connection.
		udpAddr, _ := net.ResolveUDPAddr("udp", raddr.String())
		s.handlePunchHoleSent(msg.GetPunchHoleSent(), udpAddr, false)
		return nil
	case msg.GetFetchLocalAddr() != nil:
		logClientFetchLocalAddr("TCP", raddr.String())
		return nil
	case msg.GetLocalAddr() != nil:
		// Forward LocalAddr via UDP (fire-and-forget)
		udpAddr, _ := net.ResolveUDPAddr("udp", raddr.String())
		if udpAddr != nil {
			s.handleLocalAddr(msg.GetLocalAddr(), udpAddr)
		}
		return nil
	case msg.GetIceCandidate() != nil:
		// WebRTC trickle ICE between two new peers; forward and stay silent.
		udpAddr, _ := net.ResolveUDPAddr("udp", raddr.String())
		s.handleIceCandidate(msg.GetIceCandidate(), udpAddr)
		return nil
	case msg.GetHc() != nil:
		return &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_Hc{
				Hc: &pb.HealthCheck{Token: msg.GetHc().Token},
			},
		}
	case msg.GetHttpProxyRequest() != nil:
		// Only this server's own /api/ (http_proxy.go), never another host.
		return s.handleHTTPProxyRequest(msg.GetHttpProxyRequest(), raddr)
	default:
		return nil
	}
}

// peerIDRegexp validates RustDesk peer ID format: 6-16 alphanumeric chars, hyphens, underscores.
var peerIDRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]{6,16}$`)

// isValidPeerID checks if a peer ID conforms to the expected format.
func isValidPeerID(id string) bool {
	return peerIDRegexp.MatchString(id)
}

func hostFromAddrString(addrStr string) string {
	host, _, err := net.SplitHostPort(addrStr)
	if err == nil && host != "" {
		return host
	}
	return addrStr
}

// keyedPeerMoves reports whether a heartbeat from ip over transport would move
// a live peer whose key is stored to another IP, or between WebSocket and the
// native transports. Such a peer moves only after a RegisterPk whose uuid and
// pk match: hbbs asks for the key again when the address changes. A new port
// on the same IP (NAT rebinding) is not a move.
func (s *Server) keyedPeerMoves(id string, existing *peer.Entry, ip net.IP, transport peer.ConnType) bool {
	if len(s.peerPublicKey(id, existing)) == 0 {
		return false
	}
	knownIP, knownType, ok := s.peers.Endpoint(id)
	if !ok || knownIP == nil {
		return false
	}
	if (knownType == peer.ConnWS) != (transport == peer.ConnWS) {
		return true
	}
	return !knownIP.Equal(ip)
}

// storedPeerMoves is keyedPeerMoves for a peer that is not live: its stored
// key and the last address the database holds for it.
func storedPeerMoves(stored *db.Peer, ip net.IP) bool {
	if stored == nil || len(stored.PK) == 0 {
		return false
	}
	knownIP := net.ParseIP(hostFromAddrString(strings.TrimSpace(stored.IP)))
	return knownIP != nil && !knownIP.Equal(ip)
}

func registerPeerResponse(requestPk bool) *pb.RendezvousMessage {
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RegisterPeerResponse{
			RegisterPeerResponse: &pb.RegisterPeerResponse{RequestPk: requestPk},
		},
	}
}

// handleRegisterPeer processes a heartbeat registration from a client.
// This is the most frequent message — called every ~12 seconds per device.
func (s *Server) handleRegisterPeer(msg *pb.RegisterPeer, raddr *net.UDPAddr) {
	id := msg.Id
	if id == "" {
		return
	}

	// Validate peer ID format (S7)
	if !isValidPeerID(id) {
		log.Printf("[signal] Rejected invalid peer ID format: %q from %s", id, raddr.IP)
		return
	}

	// Blocklist check (IP and ID)
	clientHost := raddr.IP.String()
	if s.blocklist != nil {
		if s.blocklist.IsIPBlocked(clientHost) {
			log.Printf("[signal] Blocked IP %s tried to register", raddr.IP)
			return
		}
		if s.blocklist.IsIDBlocked(id) {
			log.Printf("[signal] Blocked ID %s tried to register", id)
			return
		}
	}

	// Panel rename: map stale client IDs to the successor row before lookup.
	if effectiveID, ok := s.resolveRegistrationPeerID(id, clientHost, nil, nil); !ok {
		return
	} else if effectiveID != id {
		id = effectiveID
	}

	// Check if peer exists in memory map (this pod's: a peer another pod
	// held registers here as new)
	existing := s.peers.GetLocal(id)
	var dbPeer *db.Peer
	knownPeer := existing != nil
	if !knownPeer {
		if loadedPeer, err := s.db.GetPeer(id); err == nil && loadedPeer != nil {
			dbPeer = loadedPeer
			knownPeer = true
		}
	}
	if !s.allowRegistration(clientHost, id, knownPeer) {
		if knownPeer {
			log.Printf("[signal] Rate limited registration from %s for peer %s", clientHost, id)
		} else {
			log.Printf("[signal] Rate limited new registration from %s for peer %s", clientHost, id)
		}
		return
	}
	if existing != nil {
		// Reject banned peers — do not heartbeat or respond
		if existing.Banned {
			log.Printf("[signal] Rejected banned peer heartbeat: %s from %s", id, raddr.IP)
			s.revokeBannedPeerAccess(id, nil)
			return
		}
		if banned, err := s.db.IsPeerBanned(id); err != nil || banned {
			if err != nil {
				log.Printf("[signal] Failed ban check for peer heartbeat %s: %v", id, err)
			} else {
				log.Printf("[signal] Rejected banned peer heartbeat: %s from %s", id, raddr.IP)
				s.revokeBannedPeerAccess(id, nil)
			}
			return
		}

		if s.keyedPeerMoves(id, existing, raddr.IP, peer.ConnUDP) {
			log.Printf("[signal] Heartbeat for %s from new address %s: asking for its key before moving it", id, raddr)
			s.sendUDP(registerPeerResponse(true), raddr)
			return
		}
		// The server refused its key: the heartbeat does not count, and the
		// peer is asked for its key again
		if s.peers.KeyRefused(id) {
			s.sendUDP(registerPeerResponse(true), raddr)
			return
		}

		// Update heartbeat
		s.peers.UpdateHeartbeat(id, raddr, msg.Serial)

		// A peer can be back in memory after a restart before its RegisterPk
		// arrives. Restore the durable identity before deciding whether to
		// request it again, so relay responses can be signed immediately.
		livePK := s.peerPublicKey(id, existing)
		requestPk := len(livePK) == 0
		resp := &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_RegisterPeerResponse{
				RegisterPeerResponse: &pb.RegisterPeerResponse{
					RequestPk: requestPk,
				},
			},
		}
		s.sendUDP(resp, raddr)

		// Debounce database status updates — only sync every 60s per peer (P1)
		if s.peers.DBSyncDue(id, 60*time.Second) {
			s.db.UpdatePeerStatus(id, "ONLINE", raddr.IP.String(), "signal")
		}
		return
	}

	if s.rejectIfPeerSoftDeleted(id, raddr.IP.String()) {
		return
	}

	// NEW PEER — Dual Key System enrollment check.
	if !s.checkEnrollmentPermission(id, raddr.IP.String()) {
		s.enrollmentLogf(id, "Rejected new peer %s from %s (enrollment policy)", id, raddr.IP)
		if s.isPendingEnrollment(id) {
			// Keep the UDP endpoint registered, but do not request its key
			// until approval. The next heartbeat after approval will request
			// RegisterPk on the same live transport.
			s.retainPendingSignalPeer(id, raddr.String(), raddr, msg.Serial, peer.ConnUDP)
			s.sendUDP(&pb.RendezvousMessage{
				Union: &pb.RendezvousMessage_RegisterPeerResponse{
					RegisterPeerResponse: &pb.RegisterPeerResponse{RequestPk: false},
				},
			}, raddr)
		}
		s.auditRefusal(audit.ActionPeerRegistrationRejected, raddr.IP.String(), id, map[string]string{
			"reason": "enrollment_policy",
		})
		return
	}

	// Check if this peer is banned in the database (e.g. removed from memory
	// map after ban but trying to re-register)
	if banned, err := s.db.IsPeerBanned(id); err != nil || banned {
		if err != nil {
			log.Printf("[signal] Failed ban check for peer registration %s: %v", id, err)
			return
		}
		log.Printf("[signal] Rejected banned peer registration: %s from %s", id, raddr.IP)
		s.revokeBannedPeerAccess(id, nil)
		s.auditRefusal(audit.ActionPeerRegistrationRejected, raddr.IP.String(), id, map[string]string{
			"reason": "banned",
		})
		return
	}

	if dbPeer == nil {
		dbPeer, _ = s.db.GetPeer(id)
	}
	if storedPeerMoves(dbPeer, raddr.IP) {
		log.Printf("[signal] Heartbeat for stored peer %s from new address %s: asking for its key before registering it", id, raddr)
		s.sendUDP(registerPeerResponse(true), raddr)
		return
	}

	// New peer — add to memory map with the PK and UUID stored for it
	now := time.Now()
	entry := &peer.Entry{
		ID:              id,
		IP:              raddr.String(),
		UDPAddr:         raddr,
		Serial:          msg.Serial,
		ConnType:        peer.ConnUDP,
		LastReg:         now,
		FirstSeen:       now,
		HeartbeatCount:  1,
		StatusTier:      peer.StatusOnline,
		LastStatusCheck: now,
	}

	if dbPeer != nil {
		if len(dbPeer.PK) > 0 {
			entry.PK = dbPeer.PK
			log.Printf("[signal] Loaded PK from database for %s (%d bytes)", id, len(entry.PK))
		}
		if dbPeer.UUID != "" {
			entry.UUID = peerUUIDFromDB(dbPeer.UUID)
		}
	}
	// A key refused before a restart or before the entry expired stays
	// refused until the peer registers with the stored key
	entry.KeyRefused = len(entry.PK) > 0 && s.keyRefusedStored(id)

	movedFrom := s.remotePeerOwner(entry.ID)
	s.peers.Put(entry)
	s.notePeerHere(entry.ID, movedFrom)
	if entry.KeyRefused {
		s.sendUDP(registerPeerResponse(true), raddr)
		return
	}

	// The stored key signs relay answers at once, but the peer is asked for
	// its key all the same, as hbbs and the WebSocket path do: a computer
	// that comes back after a restart or a reboot with another key is then
	// refused (processRegisterPk) instead of passing as online while every
	// session fails its handshake (L438).
	s.sendUDP(registerPeerResponse(true), raddr)

	log.Printf("[signal] New peer registered: %s from %s (pk_loaded=%v)", id, raddr, len(entry.PK) > 0)
	s.db.UpdatePeerStatus(id, "ONLINE", raddr.IP.String(), "signal")
	s.publishPeerOnline(id)
}

// handleRegisterPk processes a public key registration.
func (s *Server) handleRegisterPk(msg *pb.RegisterPk, raddr *net.UDPAddr) {
	resp := s.processRegisterPk(msg, raddr.String())
	if registerPkAccepted(msg, resp) {
		s.peers.MoveToUDP(msg.Id, raddr)
	}
	s.sendUDP(resp, raddr)
}

// registerPkAccepted reports whether resp accepted msg as the identity of
// msg.Id, so the sender's transport may now carry that peer. A
// no-register-device exchange proves nothing about the id.
func registerPkAccepted(msg *pb.RegisterPk, resp *pb.RendezvousMessage) bool {
	rpk := resp.GetRegisterPkResponse()
	return rpk != nil && rpk.GetResult() == pb.RegisterPkResponse_OK && !msg.GetNoRegisterDevice()
}

// handleRegisterPkTCP handles RegisterPk over TCP (returns response).
func (s *Server) handleRegisterPkTCP(msg *pb.RegisterPk, raddr net.Addr) *pb.RendezvousMessage {
	return s.processRegisterPk(msg, raddr.String())
}

// RegisterPk size limits. The pk is an Ed25519 public key (32 bytes); the
// uuid is the machine id stock clients read from the system (36 characters
// on Windows and macOS, 32 on Linux) or the public key where there is none.
// A stored key is signed into every punch and relay answer, so its size is
// what the server sends to whoever asks.
const (
	maxRegisterPkKey  = 32
	maxRegisterPkUUID = 128
)

// processRegisterPk is the shared logic for RegisterPk handling.
func (s *Server) processRegisterPk(msg *pb.RegisterPk, addrStr string) *pb.RendezvousMessage {
	id := msg.Id
	if id == "" {
		return registerPkResponse(pb.RegisterPkResponse_SERVER_ERROR)
	}
	clientHost := hostFromAddrString(addrStr)

	// Validate peer ID format (S7)
	if !isValidPeerID(id) {
		log.Printf("[signal] Rejected invalid peer ID format in RegisterPk: %q", id)
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}
	if len(msg.Pk) > maxRegisterPkKey || len(msg.Uuid) > maxRegisterPkUUID {
		log.Printf("[signal] Rejected RegisterPk for %s from %s: pk %d bytes, uuid %d bytes", id, clientHost, len(msg.Pk), len(msg.Uuid))
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}

	// IP blocklist check
	if s.blocklist != nil {
		if s.blocklist.IsIPBlocked(clientHost) {
			log.Printf("[signal] Blocked IP %s tried RegisterPk", clientHost)
			return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
		}
		if s.blocklist.IsIDBlocked(id) {
			log.Printf("[signal] Blocked ID %s tried RegisterPk", id)
			return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
		}
	}

	// Check for ID change request
	if msg.OldId != "" {
		return s.processIDChange(msg, addrStr)
	}

	// Panel rename: map stale client IDs to the successor row before enrollment/DB checks.
	if effectiveID, ok := s.resolveRegistrationPeerID(id, clientHost, msg.Uuid, msg.Pk); !ok {
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	} else if effectiveID != id {
		id = effectiveID
		msg.Id = effectiveID
	}

	// Handle no_register_device (key-only exchange, no DB entry)
	if msg.NoRegisterDevice {
		return registerPkResponse(pb.RegisterPkResponse_OK)
	}

	// RegisterPk can be the first persistence point for stock RustDesk clients.
	// Enforce enrollment before creating a new peer row, otherwise managed/locked
	// mode can be bypassed by sending PK registration without a prior heartbeat.
	softDeleted, _ := s.db.IsPeerSoftDeleted(id)

	// SECURITY (GHSA-3v82-3gf8-fxx8): Reject PK registration for soft-deleted
	// peers. UpsertPeer would otherwise silently restore the row AND overwrite
	// the previously-stored PK with the attacker's key, completing an identity
	// takeover of a device the admin explicitly removed.
	if softDeleted {
		log.Printf("[signal] Rejected PK registration of deleted peer: %s from %s", id, clientHost)
		s.auditRefusal(audit.ActionPeerRegistrationRejected, clientHost, id, map[string]string{
			"reason": "soft_deleted",
			"stage":  "register_pk",
		})
		s.peers.Remove(id)
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}

	existingPeer, err := s.db.GetPeer(id)
	if err != nil {
		log.Printf("[signal] Failed to check peer %s before RegisterPk enrollment: %v", id, err)
		return registerPkResponse(pb.RegisterPkResponse_SERVER_ERROR)
	}
	// A RegisterPk for an id the server does not know writes a row (a peer,
	// or an approval queue entry), so it counts against the same per-address
	// limit as a heartbeat for a new id.
	if existingPeer == nil && s.peers.Get(id) == nil && !s.allowRegistration(clientHost, id, false) {
		log.Printf("[signal] Rate limited RegisterPk for new peer %s from %s", id, clientHost)
		return registerPkResponse(pb.RegisterPkResponse_TOO_FREQUENT)
	}
	if existingPeer == nil && !s.checkEnrollmentPermission(id, clientHost) {
		s.enrollmentLogf(id, "Rejected new peer PK registration: %s from %s (enrollment policy)", id, clientHost)
		// A pending managed peer may already have a retained signal transport.
		// Keep it so approval can authorize the existing connection; an
		// untracked registration is still removed as before.
		if s.isPendingEnrollment(id) {
			s.notePendingRegisterUUID(id, msg.Uuid)
		}
		if !s.isPendingEnrollment(id) || s.peers.Get(id) == nil {
			s.peers.Remove(id)
		}
		return registerPkResponse(pb.RegisterPkResponse_NOT_DEPLOYED)
	}

	// Check ban status
	banned, err := s.db.IsPeerBanned(id)
	if err != nil {
		log.Printf("[signal] Failed ban check before RegisterPk for %s: %v", id, err)
		return registerPkResponse(pb.RegisterPkResponse_SERVER_ERROR)
	}
	if banned {
		log.Printf("[signal] Rejected banned peer: %s", id)
		s.revokeBannedPeerAccess(id, nil)
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}

	// The identity stored for the id, live or persisted. After a restart
	// peer.Map is empty; the persisted identity still binds the id. Empty
	// stored fields remain enrollable for legacy rows and first enrollment.
	storedUUID, storedPK, _ := s.peers.Keys(id)
	if existingPeer != nil {
		if len(storedUUID) == 0 && existingPeer.UUID != "" {
			storedUUID = peerUUIDFromDB(existingPeer.UUID)
		}
		if len(storedPK) == 0 && len(existingPeer.PK) > 0 {
			storedPK = append([]byte(nil), existingPeer.PK...)
		}
	}

	// Existing identity is immutable through RegisterPk, and nothing is
	// changed or bound for a known id without both fields matching. hbbs
	// drops a RegisterPk with an empty uuid or pk without an answer; stock
	// clients always send both.
	if len(storedUUID) > 0 || len(storedPK) > 0 {
		if len(msg.Uuid) == 0 || len(msg.Pk) == 0 {
			log.Printf("[signal] Dropped RegisterPk for known peer %s from %s without uuid or pk", id, clientHost)
			return nil
		}
		if len(storedUUID) > 0 && !peerUUIDEqual(storedUUID, msg.Uuid) {
			log.Printf("[signal] UUID mismatch for %s: registered=%x, received=%x",
				id, storedUUID, msg.Uuid)
			return registerPkResponse(pb.RegisterPkResponse_UUID_MISMATCH)
		}
		if len(storedPK) > 0 && !bytes.Equal(storedPK, msg.Pk) {
			log.Printf("[signal] PK mismatch for %s", id)
			s.refuseKey(id, addrStr)
			return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
		}
	}
	s.acceptKey(id)

	uuidBytes, pk := storedUUID, storedPK
	if len(msg.Uuid) > 0 {
		uuidBytes = normalizePeerUUIDBytes(msg.Uuid)
	}
	if len(msg.Pk) > 0 {
		pk = append([]byte(nil), msg.Pk...)
	}
	// Bind exact ip:port so FindByAddr can authorize TCP/WS-only RegisterPk
	// (viewer-only outbound when the OS service is not sending UDP heartbeats).
	// Prefer same-TCP-session bind (tcpSessionPeerID) when RegisterPk keep-alive
	// leaves the connection open for a following PunchHole.
	s.peers.RecordRegisterPk(id, uuidBytes, pk, addrStr)
	s.bindTCPSessionPeer(addrStr, id)

	// Persist to database
	dbPeer := &db.Peer{
		ID:     id,
		UUID:   fmt.Sprintf("%x", uuidBytes),
		PK:     pk,
		Status: "ONLINE",
	}
	if err := s.db.UpsertPeer(dbPeer); err != nil {
		log.Printf("[signal] Failed to upsert peer %s: %v", id, err)
	} else {
		// Bind peers.user when an active RustDesk client login exists for this device.
		db.ApplyActiveSessionOwner(s.db, id, dbPeer.UUID)
	}

	log.Printf("[signal] PK registered for %s (pk=%d bytes)", id, len(msg.Pk))

	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RegisterPkResponse{
			RegisterPkResponse: &pb.RegisterPkResponse{
				Result:    pb.RegisterPkResponse_OK,
				KeepAlive: 12, // Suggest 12s heartbeat interval
			},
		},
	}
}

// processIDChange handles old_id → new id change requests.
//
// SECURITY (audit C2, 2026-11-13): the change was applied for anyone who knew
// an existing peer id. `RegisterPk` with `old_id=<victim>`, no `pk`, and no
// matching UUID moved (and deleted) the victim row, which under open
// enrollment let a second registration claim the freed id.
//
// Stock RustDesk change-ID sends `old_id` + `id` + machine UUID and *no* pk
// (see `change_id_shared` in the client), so an empty pk must stay valid — but
// only when the caller proves the identity another way. This now mirrors hbbs:
// accept a change when the supplied pk matches the stored pk, or when the
// supplied UUID matches the stored UUID. Everything else is rejected.
func (s *Server) processIDChange(msg *pb.RegisterPk, addrStr string) *pb.RendezvousMessage {
	oldID := msg.OldId
	newID := msg.Id

	if !isValidPeerID(oldID) {
		log.Printf("[signal] Rejected invalid old peer ID in ID change: %q", oldID)
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}
	if !isValidPeerID(newID) {
		log.Printf("[signal] Rejected invalid new peer ID in ID change: %q", newID)
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}

	oldPeer, err := s.db.GetPeer(oldID)
	if err != nil {
		log.Printf("[signal] Failed to load old ID %s before ID change: %v", oldID, err)
		return registerPkResponse(pb.RegisterPkResponse_SERVER_ERROR)
	}
	if oldPeer == nil {
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}

	// RustDesk 1.4.x change-ID sends RegisterPk without pk (see change_id_shared).
	// A supplied pk must match; an omitted pk is only acceptable together with a
	// matching UUID below (audit C2).
	effectivePK := msg.Pk
	if len(effectivePK) == 0 {
		effectivePK = oldPeer.PK
	} else if len(oldPeer.PK) > 0 && !bytes.Equal(oldPeer.PK, effectivePK) {
		log.Printf("[signal] Rejected ID change %s → %s: PK mismatch", oldID, newID)
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}

	// Proof of identity: matching PK, or matching UUID (machine uid bytes).
	// The UUID comparison used to be limited to 16-byte wire values, which let
	// any caller skip the check by sending a different length.
	storedUUID := peerUUIDFromDB(oldPeer.UUID)
	pkProven := len(msg.Pk) > 0 && len(oldPeer.PK) > 0 && bytes.Equal(oldPeer.PK, msg.Pk)
	uuidProven := len(msg.Uuid) > 0 && len(storedUUID) > 0 && peerUUIDEqual(storedUUID, msg.Uuid)
	// A row with no stored identity has nothing to steal; keep legacy rows working.
	noStoredIdentity := len(oldPeer.PK) == 0 && len(storedUUID) == 0
	if !pkProven && !uuidProven && !noStoredIdentity {
		log.Printf("[signal] Rejected ID change %s → %s: no matching PK or UUID", oldID, newID)
		s.auditRefusal(audit.ActionPeerRegistrationRejected, hostFromAddrString(addrStr), oldID, map[string]string{
			"reason": "id_change_without_identity_proof",
			"stage":  "id_change",
			"new_id": newID,
		})
		return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
	}

	// A TCP session already bound to a different peer must not change somebody
	// else's identity, even with a leaked UUID.
	if addrStr != "" {
		if bound := s.peerIDBySessionAddr(addrStr); bound != "" && bound != oldID {
			log.Printf("[signal] Rejected ID change %s → %s: address bound to %s", oldID, newID, bound)
			return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
		}
	}

	// Validate new ID doesn't exist
	existing := s.peers.Get(newID)
	if existing != nil {
		return registerPkResponse(pb.RegisterPkResponse_ID_EXISTS)
	}

	targetState, err := s.db.GetPeerIDState(newID)
	if err != nil {
		log.Printf("[signal] Failed to check target ID %s before ID change: %v", newID, err)
		return registerPkResponse(pb.RegisterPkResponse_SERVER_ERROR)
	}
	if targetState == db.PeerIDActive || targetState == db.PeerIDSoftDeleted {
		return registerPkResponse(pb.RegisterPkResponse_ID_EXISTS)
	}

	// Perform the change
	if err := s.db.ChangePeerID(oldID, newID, "client"); err != nil {
		if errors.Is(err, db.ErrPeerIDExists) || errors.Is(err, db.ErrPeerIDSoftDeleted) {
			return registerPkResponse(pb.RegisterPkResponse_ID_EXISTS)
		}
		if errors.Is(err, db.ErrPeerNotFound) {
			return registerPkResponse(pb.RegisterPkResponse_NOT_SUPPORT)
		}
		log.Printf("[signal] ID change %s → %s failed: %v", oldID, newID, err)
		return registerPkResponse(pb.RegisterPkResponse_SERVER_ERROR)
	}

	// Move the in-memory identity without closing its persistent registration.
	if _, moved := s.peers.Rename(oldID, newID); moved {
		var newUUID []byte
		if len(msg.Uuid) > 0 {
			newUUID = normalizePeerUUIDBytes(msg.Uuid)
		}
		s.peers.SetKeys(newID, newUUID, effectivePK)
	}

	log.Printf("[signal] ID changed: %s → %s", oldID, newID)
	if s.eventBus != nil {
		s.eventBus.Publish(events.Event{
			Type: events.EventPeerIDChanged,
			Data: map[string]string{
				"old_id": oldID,
				"new_id": newID,
				"source": "client",
			},
		})
	}
	return registerPkResponse(pb.RegisterPkResponse_OK)
}

// handlePunchHoleRequest processes a hole-punch request from the initiator.
func (s *Server) handlePunchHoleRequest(msg *pb.PunchHoleRequest, raddr *net.UDPAddr) {
	connection := s.cfg.ConnectionSettings()
	targetID := msg.Id
	if targetID == "" {
		return
	}
	if !isValidPeerID(targetID) {
		log.Printf("[signal] PunchHoleRequest from %s for invalid target id %q", raddr, targetID)
		s.sendUDP(s.punchHoleUnauthorizedResponse(), raddr)
		return
	}

	log.Printf("[signal] PunchHoleRequest from %s for target %s", raddr, targetID)

	initiatorID, ok := s.requireAuthorizedInitiator(raddr, targetID, msg.GetToken(), msg.GetUdpPort())
	if !ok {
		s.sendUDP(s.punchHoleUnauthorizedResponse(), raddr)
		return
	}
	policy := s.sessionPolicy(msg.GetToken(), raddr, false, msg.GetConnType())
	s.limitToQuickSupport(&policy, targetID, msg.GetConnType())
	if policy.refusal != "" {
		s.refuseForFeature(raddr, initiatorID, targetID, policy)
		s.sendUDP(featureRefusedPunchResponse(policy.refusal), raddr)
		return
	}
	s.logAuthorizedInitiator(raddr, initiatorID, targetID, msg.GetToken(), "punch_hole")
	permissions := policy.permissions

	target := s.peers.Get(targetID)

	// Target not found or offline
	if target == nil || !target.Reachable(config.RegTimeout) {
		if target == nil {
			log.Printf("[signal] PunchHole: target %s not found in peer map", targetID)
		} else {
			log.Printf("[signal] PunchHole: target %s expired (last heartbeat: %v ago)", targetID, time.Since(target.LastReg))
		}
		resp := &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_PunchHoleResponse{
				PunchHoleResponse: &pb.PunchHoleResponse{
					Failure:     pb.PunchHoleResponse_OFFLINE,
					RelayServer: s.getRelayServer(),
				},
			},
		}
		s.sendUDP(resp, raddr)
		return
	}

	// Target policy is durable; do not trust a stale live-peer entry after an
	// administrator has disabled, banned, or removed the device.
	if target.Banned || !s.targetAcceptsInboundSession(targetID) {
		resp := &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_PunchHoleResponse{
				PunchHoleResponse: &pb.PunchHoleResponse{
					Failure: pb.PunchHoleResponse_OFFLINE,
				},
			},
		}
		s.sendUDP(resp, raddr)
		return
	}

	if refuse := s.admitSession(nil, "", initiatorID, targetID, policy.account, policy.consoleSession); refuse != "" {
		s.sendUDP(punchHoleOfflineResponse(), raddr)
		return
	}

	route := s.chooseRelay(relayRouteRequest{
		base: s.getRelayServer(), a: raddr, b: target.UDPAddr, target: target,
		policyPeers: []string{initiatorID, targetID},
	})
	relayServer, sameNetwork, hairpin := route.Addr, route.SameNetwork, route.Hairpin
	if sameNetwork {
		log.Printf("[signal] LAN detected: %s and %s on same network, relay=%s", raddr.IP, target.UDPAddr.IP, relayServer)
	}
	if hairpin {
		log.Printf("[signal] PunchHole: shared public IP %s detected (NAT hairpin) → forcing relay for %s",
			raddr.IP, targetID)
	}

	log.Printf("[signal] PunchHole: target %s found (addr=%s, status=%s, lastReg=%v ago), relay=%s",
		targetID, target.UDPAddr, target.StatusTier, time.Since(target.LastReg), relayServer)

	s.recordConnectionSession(raddr, initiatorID, targetID, msg.GetToken(), "punch_hole", "")

	// Correlate initiator identity (and the account behind the request)
	// for a later RelayResponse on shared NAT.
	s.storePendingRelayFor(targetID, raddr, raddr, "", initiatorID, policy.account, policy.consoleSession)

	// If force relay or always use relay
	if msg.ForceRelay || connection.AlwaysUseRelay || hairpin ||
		isLegacyOutboundInitiator(initiatorID) ||
		s.shouldForceRelayForPeers(initiatorID, targetID) ||
		s.requiresRelayOnlyCompatibility(targetID) {
		log.Printf("[signal] PunchHole: force relay for %s", targetID)
		s.sendRelayResponse(target, raddr, msg, route, initiatorID, policy)
		return
	}

	// Native peers on the same LAN must exchange their actual listener
	// endpoint before the initiator receives a PunchHoleResponse. A public
	// registration endpoint marked is_local is not a valid LAN candidate.
	if sameNetwork && target.ConnType != peer.ConnWS {
		pending, started := s.beginLANExchange(
			targetID, target, initiatorID, raddr, peer.ConnUDP,
			relayServer, msg.SocketAddrV6, permissions,
		)
		if started {
			return
		}
		if pending != nil {
			s.sendUDP(pending.fallback, raddr)
		} else {
			s.sendUDP(s.lanFallbackResponse(targetID, target, relayServer, nil), raddr)
		}
		return
	}

	// Send PunchHole to the TARGET peer (tell it the initiator's address)
	punchHole := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_PunchHole{
			PunchHole: &pb.PunchHole{
				SocketAddr:   crypto.EncodeAddr(raddr),
				RelayServer:  relayServer,
				NatType:      msg.NatType,
				UdpPort:      msg.UdpPort,
				ForceRelay:   msg.ForceRelay,
				UpnpPort:     msg.UpnpPort,
				SocketAddrV6: msg.SocketAddrV6,
				// Recent clients negotiate a WebRTC transport; the offer must reach
				// the peer verbatim or two new peers cannot establish a session.
				WebrtcSdpOffer:     msg.WebrtcSdpOffer,
				ControlPermissions: permissions,
			},
		},
	}

	if target.UDPAddr != nil {
		s.sendUDP(punchHole, target.UDPAddr)
	} else {
		// Target is connected via TCP/WS (e.g. logged in): forward PunchHole
		// over its active connection so it can still open its NAT for P2P.
		s.sendToPeer(targetID, punchHole)
	}

	// Send PunchHoleResponse to the INITIATOR with signed PK for E2E.
	// The original Rust hbbs sends PunchHoleResponse (not PunchHoleSent) to the initiator.
	// PunchHoleResponse has a 'pk' field for E2E key verification;
	// PunchHoleSent does NOT have a pk field, so using it breaks E2E encryption.
	targetAddr := encodePeerSocketAddr(target)

	// Sign the target's PK with server's Ed25519 key for E2E verification.
	var signedPk []byte
	targetPK := s.peerPublicKey(targetID, target)
	if len(targetPK) > 0 {
		signed, err := s.kp.SignIdPk(targetID, targetPK)
		if err != nil {
			log.Printf("[signal] PunchHole: failed to sign PK for %s: %v", targetID, err)
		} else {
			signedPk = signed
			log.Printf("[signal] PunchHole: signed PK for %s (%d bytes)", targetID, len(signedPk))
		}
	}

	// When peers are on the same LAN, set IsLocal instead of NatType so the
	// client knows to use direct LAN addresses (FetchLocalAddr exchange).
	phr := &pb.PunchHoleResponse{
		SocketAddr:  targetAddr,
		Pk:          signedPk,
		RelayServer: relayServer,
	}
	if sameNetwork {
		phr.Union = &pb.PunchHoleResponse_IsLocal{IsLocal: true}
	} else {
		phr.Union = &pb.PunchHoleResponse_NatType{NatType: pb.NatType(target.NATType)}
	}
	phr = ensurePunchHoleSocketAddr(phr, targetID, relayServer)

	resp := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_PunchHoleResponse{
			PunchHoleResponse: phr,
		},
	}

	// P2P-first: when the peers are not on the same LAN, defer
	// this response and wait for the target's PunchHoleSent, which carries the
	// target's actual punched address and lets direct P2P succeed. If the
	// target stays silent past the grace period, the scheduled fallback sends
	// this relay-capable response so the client can fall back to relay instead
	// of hanging. handlePunchHoleSent cancels the fallback once the genuine
	// response is forwarded.
	if connection.P2PFirst && !sameNetwork && len(phr.SocketAddr) > 0 {
		raddrCopy := *raddr
		s.schedulePunchFallback(normalizeAddrKey(raddr.String()), func() {
			log.Printf("[signal] P2P-first: target %s did not complete hole punch in time, sending relay fallback to %s",
				targetID, raddrCopy.String())
			s.sendUDP(resp, &raddrCopy)
		})
		return
	}

	s.sendUDP(resp, raddr)
}

// handlePunchHoleRequestTCP handles punch hole over TCP/WS.
//
// Matching the UDP handler behavior for WAN peers: send a PunchHoleResponse
// with the target's signed PK, socket address, relay server, and NAT type.
// Genuine native LAN peers use the asynchronous FetchLocalAddr exchange below.
//
// Previous behavior (returning nil and waiting for the target's PunchHoleSent)
// caused "Failed to secure tcp: deadline has elapsed" timeouts when:
//   - The target was behind a strict NAT and didn't receive the UDP PunchHole
//   - The RustDesk client used TCP signaling (e.g. when logged in with a token)
//   - ForceRelay was set but the TCP path didn't handle it
//
// The TCP connection is kept alive (keepAlive=true via logAndCheckKeepAlive) so
// the server can still forward PunchHoleSent/RelayResponse from the target if
// they arrive later — this provides an update but is no longer required for the
// initiator to proceed.
func (s *Server) handlePunchHoleRequestTCP(msg *pb.PunchHoleRequest, raddr *net.UDPAddr) *pb.RendezvousMessage {
	return s.handlePunchHoleRequestTCPWithHint(msg, raddr, peer.ConnTCP)
}

func (s *Server) handlePunchHoleRequestTCPWithHint(msg *pb.PunchHoleRequest, raddr *net.UDPAddr, initiatorHint peer.ConnType) *pb.RendezvousMessage {
	return s.punchHoleRequestTCP(msg, raddr, initiatorHint, false)
}

// punchHoleRequestTCP is handlePunchHoleRequestTCPWithHint; panel is true
// on the connection of the panel's web client.
func (s *Server) punchHoleRequestTCP(msg *pb.PunchHoleRequest, raddr *net.UDPAddr, initiatorHint peer.ConnType, panel bool) *pb.RendezvousMessage {
	connection := s.cfg.ConnectionSettings()
	if raddr == nil {
		log.Printf("[signal] PunchHoleRequest (TCP): nil address, ignoring")
		return nil
	}
	targetID := msg.Id
	if targetID == "" {
		return nil
	}
	if !isValidPeerID(targetID) {
		log.Printf("[signal] PunchHoleRequest (TCP) from %s for invalid target id %q", raddr, targetID)
		return s.punchHoleUnauthorizedResponse()
	}

	log.Printf("[signal] PunchHoleRequest (TCP) from %s for target %s", raddr, targetID)

	initiatorID, ok := s.authorizeInitiator(raddr, targetID, msg.GetToken(), msg.GetUdpPort(), panel)
	if !ok {
		return s.punchHoleUnauthorizedResponse()
	}
	policy := s.sessionPolicy(msg.GetToken(), raddr, panel, msg.GetConnType())
	s.limitToQuickSupport(&policy, targetID, msg.GetConnType())
	if policy.refusal != "" {
		s.refuseForFeature(raddr, initiatorID, targetID, policy)
		return featureRefusedPunchResponse(policy.refusal)
	}
	s.logAuthorizedInitiator(raddr, initiatorID, targetID, msg.GetToken(), "punch_hole")
	permissions := policy.permissions

	target := s.peers.Get(targetID)
	if target == nil || !target.Reachable(config.RegTimeout) {
		if target == nil {
			log.Printf("[signal] PunchHole (TCP): target %s not found in peer map", targetID)
		} else {
			log.Printf("[signal] PunchHole (TCP): target %s expired (last heartbeat: %v ago)", targetID, time.Since(target.LastReg))
		}
		return &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_PunchHoleResponse{
				PunchHoleResponse: &pb.PunchHoleResponse{
					Failure:     pb.PunchHoleResponse_OFFLINE,
					RelayServer: s.getRelayServer(),
				},
			},
		}
	}

	// Reject disabled, banned, or soft-deleted targets as offline.
	if target.Banned || !s.targetAcceptsInboundSession(targetID) {
		log.Printf("[signal] PunchHole (TCP): target %s is unavailable, rejecting", targetID)
		return punchHoleOfflineResponse()
	}
	if refuse := s.admitSession(nil, "", initiatorID, targetID, policy.account, policy.consoleSession); refuse != "" {
		return punchHoleOfflineResponse()
	}

	route := s.chooseRelay(relayRouteRequest{
		base: s.getRelayServer(), a: raddr, b: target.UDPAddr, target: target,
		policyPeers: []string{initiatorID, targetID},
	})
	relayServer, sameNetwork, hairpin := route.Addr, route.SameNetwork, route.Hairpin
	if sameNetwork {
		log.Printf("[signal] LAN detected (TCP): %s and %s on same network, relay=%s", raddr.IP, target.UDPAddr.IP, relayServer)
	}
	if hairpin {
		log.Printf("[signal] PunchHole (TCP): shared public IP %s detected (NAT hairpin) → forcing relay for %s",
			raddr.IP, targetID)
	}

	log.Printf("[signal] PunchHole (TCP): target %s found (addr=%s, status=%s), relay=%s",
		targetID, target.UDPAddr, target.StatusTier, relayServer)

	s.recordConnectionSession(raddr, initiatorID, targetID, msg.GetToken(), "punch_hole", "")

	// Correlate initiator identity for a later RelayResponse on shared NAT,
	// and the address the target sees for a later PunchHoleSent.
	s.storePendingRelayFor(targetID, raddr, relayAdvertisedAddr(s, raddr, initiatorID, initiatorHint), "", initiatorID, policy.account, policy.consoleSession)

	// ForceRelay or AlwaysUseRelay: return PunchHoleResponse with SYMMETRIC NAT
	// type instead of RelayResponse. This tells the client that direct P2P is
	// impossible and it should fall back to relay via RequestRelay.
	//
	// The client will then send RequestRelay (with its own UUID) on this same
	// TCP connection. handleRequestRelayTCP will forward it to the target and
	// return RelayResponse to the initiator. Both sides connect to relay with
	// the SAME client-generated UUID, ensuring relay pairing succeeds.
	//
	// Previously, returning RelayResponse directly with a server-generated UUID
	// caused UUID mismatch: some RustDesk client versions ignore the UUID from
	// a RelayResponse received in response to PunchHoleRequest (they expect
	// PunchHoleResponse), generate their own UUID, and connect to relay with it
	// — while the target connects with the server's UUID. This broke relay
	// pairing every time.
	if msg.ForceRelay || connection.AlwaysUseRelay || hairpin ||
		isLegacyOutboundInitiator(initiatorID) ||
		s.shouldForceRelayForPeers(initiatorID, targetID) ||
		s.requiresRelayOnlyCompatibility(targetID) {
		log.Printf("[signal] PunchHole (TCP): force relay for %s (returning SYMMETRIC to let client drive relay UUID)", targetID)

		// Do NOT punch the target here.
		//
		// Production proved a punch changes the target's role: with one present it
		// treats itself as relay initiator and answers RelayResponse with its own
		// uuid and id (10:07: uuid=5d0f61e5, id=275129227). Without it the answer
		// carries an empty uuid (09:11: uuid=, id=), which is the shape
		// handleRelayResponseForward recovers from the pending store.
		//
		// The target still receives RequestRelay carrying the initiator address,
		// which is all it needs to answer, and the initiator still gets its prompt
		// RelayResponse below.
		var signedPk []byte
		targetPK := s.peerPublicKey(targetID, target)
		if len(targetPK) > 0 {
			signed, err := s.kp.SignIdPk(target.ID, targetPK)
			if err != nil {
				log.Printf("[signal] PunchHole (TCP): failed to sign PK for %s: %v", targetID, err)
			} else {
				signedPk = signed
			}
		}

		targetAddr := encodePeerSocketAddr(target)

		phr := ensurePunchHoleSocketAddr(&pb.PunchHoleResponse{
			SocketAddr:  targetAddr,
			Pk:          signedPk,
			RelayServer: relayServer,
			Union:       &pb.PunchHoleResponse_NatType{NatType: pb.NatType_SYMMETRIC},
		}, targetID, relayServer)

		return &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_PunchHoleResponse{
				PunchHoleResponse: phr,
			},
		}
	}

	if sameNetwork && initiatorHint != peer.ConnWS && target.ConnType != peer.ConnWS {
		pending, started := s.beginLANExchange(
			targetID, target, initiatorID, raddr, peer.ConnTCP,
			relayServer, msg.SocketAddrV6, permissions,
		)
		if started {
			return nil
		}
		if pending != nil {
			return pending.fallback
		}
		return s.lanFallbackResponse(targetID, target, relayServer, nil)
	}

	// Forward PunchHole to the TARGET peer (supports UDP, TCP, and WebSocket targets).
	advertisedAddr := relayAdvertisedAddr(s, raddr, initiatorID, initiatorHint)
	if advertisedAddr == nil {
		return s.punchHoleUnauthorizedResponse()
	}
	punchHole := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_PunchHole{
			PunchHole: &pb.PunchHole{
				SocketAddr:         crypto.EncodeAddr(advertisedAddr),
				RelayServer:        relayServer,
				NatType:            msg.NatType,
				UdpPort:            msg.UdpPort,
				ForceRelay:         msg.ForceRelay,
				UpnpPort:           msg.UpnpPort,
				SocketAddrV6:       msg.SocketAddrV6,
				WebrtcSdpOffer:     msg.WebrtcSdpOffer,
				ControlPermissions: permissions,
			},
		},
	}
	if s.sendToPeer(targetID, punchHole) {
		log.Printf("[signal] PunchHole (TCP): forwarded to target %s (connType=%s)", targetID, target.ConnType)
	}

	// Sign the target's PK with server's Ed25519 key for E2E verification.
	var signedPk []byte
	targetPK := s.peerPublicKey(targetID, target)
	if len(targetPK) > 0 {
		signed, err := s.kp.SignIdPk(targetID, targetPK)
		if err != nil {
			log.Printf("[signal] PunchHole (TCP): failed to sign PK for %s: %v", targetID, err)
		} else {
			signedPk = signed
			log.Printf("[signal] PunchHole (TCP): signed PK for %s (%d bytes)", targetID, len(signedPk))
		}
	}

	// Send immediate PunchHoleResponse to the TCP initiator — matching the UDP
	// handler's behavior.  This includes the target's signed PK, socket address,
	// relay server, and NAT type so the client can proceed immediately.
	targetAddr := encodePeerSocketAddr(target)

	phr := &pb.PunchHoleResponse{
		SocketAddr:  targetAddr,
		Pk:          signedPk,
		RelayServer: relayServer,
	}
	if sameNetwork {
		phr.Union = &pb.PunchHoleResponse_IsLocal{IsLocal: true}
	} else {
		phr.Union = &pb.PunchHoleResponse_NatType{NatType: pb.NatType(target.NATType)}
	}
	phr = ensurePunchHoleSocketAddr(phr, targetID, relayServer)

	resp := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_PunchHoleResponse{
			PunchHoleResponse: phr,
		},
	}

	// P2P-first: for non-LAN peers, defer this response and wait
	// for the target's PunchHoleSent, which carries the target's actual punched
	// address and lets direct P2P succeed. The TCP connection is already kept
	// alive (keepAlive via logAndCheckKeepAlive) and registered in
	// tcpPunchConns, so handlePunchHoleSent can forward the genuine response
	// over it. If the target stays silent past the grace period, the scheduled
	// fallback forwards this relay-capable response so the client can fall back
	// to relay instead of hanging (preserving the Phase 7 timeout fix).
	if connection.P2PFirst && !sameNetwork && len(phr.SocketAddr) > 0 {
		initiatorKey := normalizeAddrKey(raddr.String())
		s.schedulePunchFallback(initiatorKey, func() {
			log.Printf("[signal] P2P-first (TCP): target %s did not complete hole punch in time, forwarding relay fallback to %s",
				targetID, initiatorKey)
			s.forwardToInitiator(initiatorKey, resp)
		})
		return nil
	}

	return resp
}

// handlePunchHoleSent processes a PunchHoleSent message from the target peer.
// This is sent by the target (B) after it receives PunchHole from the signal
// server.  "PunchHoleSent" means "B is ready to accept a direct connection".
//
// The signal server converts this to a PunchHoleResponse and forwards it to the
// initiator (A).  For TCP initiators the response goes via tcpPunchConns; for
// UDP initiators it goes directly via UDP.
//
// PunchHoleSent fields: socket_addr (initiator A's addr), id (target B's ID),
// relay_server, nat_type, version.
//
// PunchHoleResponse fields: socket_addr (target B's addr, encoded), pk (target
// B's public key), relay_server, nat_type.
func (s *Server) handlePunchHoleSent(phs *pb.PunchHoleSent, senderAddr *net.UDPAddr, viaUDP bool) {
	if phs == nil || len(phs.SocketAddr) == 0 {
		return
	}

	// Decode the initiator's address from socket_addr.
	initiatorAddr, err := crypto.DecodeAddr(phs.SocketAddr)
	if err != nil {
		log.Printf("[signal] PunchHoleSent: cannot decode socket_addr: %v", err)
		return
	}

	transport := "TCP"
	if viaUDP {
		transport = "UDP"
	}
	log.Printf("[signal] %s PunchHoleSent from %s for initiator %s (id=%q)",
		transport, senderAddr, initiatorAddr, phs.Id)

	targetID := phs.Id

	// Fallback: if phs.Id is empty, try to identify the sender by IP lookup.
	// Older RustDesk clients may not populate the id field in PunchHoleSent.
	if targetID == "" {
		if n := s.peers.CountByIP(senderAddr.IP); n > 1 {
			log.Printf("[signal] PunchHoleSent: ambiguous IP lookup for %s (%d peers) — cannot resolve empty id", senderAddr.IP, n)
		} else if entry := s.peers.FindByIP(senderAddr.IP); entry != nil {
			targetID = entry.ID
			log.Printf("[signal] PunchHoleSent: resolved sender %s to peer %s via IP lookup", senderAddr, targetID)
		}
	}

	// The answer goes to the address inside the packet, so only the peer it
	// names may send it, and only for a punch that initiator asked for.
	// Stock clients send PunchHoleSent from a new socket: the IP is the
	// target's registered one, the port is not.
	if !s.senderSpeaksForPeer(targetID, senderAddr) {
		log.Printf("[signal] PunchHoleSent for %q from %s dropped: not the target's address", targetID, senderAddr)
		return
	}
	if s.getPendingRelay(targetID, initiatorAddr) == nil && s.getPendingRelayByAdvertised(targetID, initiatorAddr) == nil {
		log.Printf("[signal] PunchHoleSent from %s for %q dropped: no punch of initiator %s pending", senderAddr, targetID, initiatorAddr)
		return
	}

	// Sign the target's public key for E2E verification. RustDesk clients
	// expect signed IdPk in NaCl format: [ signature | IdPk protobuf ]
	var signedPk []byte
	target := s.peers.Get(targetID)
	if targetPK := s.peerPublicKey(targetID, target); target != nil && len(targetPK) > 0 {
		signed, err := s.kp.SignIdPk(targetID, targetPK)
		if err != nil {
			log.Printf("[signal] Failed to sign PK for %s: %v", targetID, err)
		} else {
			signedPk = signed
			log.Printf("[signal] Signed PK for %s: %d bytes", targetID, len(signedPk))
		}
	}

	if len(signedPk) == 0 {
		log.Printf("[signal] WARNING: PunchHoleSent from %s — no PK available for target %q, E2E will not be established", senderAddr, targetID)
	}

	// Build PunchHoleResponse for the initiator.
	// socket_addr = target's (sender's) address, pk = SIGNED target's public key.
	// LAN detection: set is_local only for genuine LAN cases. Shared public IP
	// peers keep the public relay to avoid NAT hairpin failures.
	route := s.chooseRelay(relayRouteRequest{
		base: s.sanitizeClientRelayAddress(phs.RelayServer), a: senderAddr, b: initiatorAddr,
	})
	relayServer, sameNetwork, hairpin := route.Addr, route.SameNetwork, route.Hairpin
	if sameNetwork {
		log.Printf("[signal] PunchHoleSent LAN detected: %s and %s on same network, relay=%s", senderAddr.IP, initiatorAddr.IP, relayServer)
	}
	if hairpin {
		log.Printf("[signal] PunchHoleSent shared public IP %s detected (NAT hairpin) → keeping public relay=%s", senderAddr.IP, relayServer)
	}

	// Remember the relay the peer itself advertised, verbatim.
	//
	// The peer validates an incoming relay request against this value, so it must
	// not be rewritten: check_port() normalises a portless host to RELAY_PORT, so
	// storing what the peer sent is always the best match for its own config.
	if phs.RelayServer != "" {
		s.peers.SetRelayServer(targetID, phs.RelayServer)
	}

	phr := &pb.PunchHoleResponse{
		SocketAddr:  crypto.EncodeAddr(senderAddr),
		Pk:          signedPk,
		RelayServer: relayServer,
		// WebRTC answer from the target; without it two new peers cannot finish
		// transport negotiation and fall back to a relay path that never pairs.
		WebrtcSdpAnswer: phs.WebrtcSdpAnswer,
	}
	if sameNetwork {
		phr.Union = &pb.PunchHoleResponse_IsLocal{IsLocal: true}
	} else {
		phr.Union = &pb.PunchHoleResponse_NatType{NatType: phs.NatType}
	}
	phr = ensurePunchHoleSocketAddr(phr, targetID, relayServer)

	resp := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_PunchHoleResponse{
			PunchHoleResponse: phr,
		},
	}

	addrStr := normalizeAddrKey(initiatorAddr.String())

	// P2P-first: the target completed hole punching, so cancel any
	// scheduled relay fallback for this initiator before delivering the genuine
	// PunchHoleResponse (which carries the target's real punched address).
	if s.cancelPunchFallback(addrStr) {
		log.Printf("[signal] P2P-first: cancelled relay fallback for %s — direct P2P response incoming", addrStr)
	}

	// Try TCP then WebSocket delivery (initiator may be on either transport).
	if s.forwardToInitiator(addrStr, resp) {
		log.Printf("[signal] PunchHoleResponse forwarded to %s (target=%s)", addrStr, targetID)
		return
	}

	// UDP delivery — send directly if we came from UDP, or look up the peer.
	if viaUDP {
		s.sendUDP(resp, initiatorAddr)
		log.Printf("[signal] PunchHoleResponse sent via UDP to %s (target=%s)", initiatorAddr, targetID)
		return
	}

	// TCP source but no TCP conn for initiator — try peer registry.
	entry := s.peers.FindByIP(initiatorAddr.IP)
	if entry != nil && entry.UDPAddr != nil {
		s.sendUDP(resp, entry.UDPAddr)
		log.Printf("[signal] PunchHoleResponse sent to peer %s at %s via UDP (target=%s)", entry.ID, entry.UDPAddr, targetID)
		return
	}

	log.Printf("[signal] PunchHoleResponse: cannot deliver to %s (target=%s)", addrStr, targetID)
}

// handleRequestRelay forwards relay setup request to target peer.
func (s *Server) handleRequestRelay(msg *pb.RequestRelay, raddr *net.UDPAddr) {
	targetID := msg.Id

	// Generate UUID if the client sent an empty one. This happens when hole-punch
	// fails after receiving PunchHoleResponse (which has no uuid field) and the
	// client retries with RequestRelay. Without a valid UUID, the relay server
	// rejects both connections.
	relayUUID := msg.Uuid
	if relayUUID == "" {
		relayUUID = uuid.New().String()
		log.Printf("[signal] RequestRelay: client %s sent empty UUID, generated %s", raddr, relayUUIDShort(relayUUID))
	}

	relayServer := s.sanitizeClientRelayAddress(msg.RelayServer)
	if !isValidPeerID(targetID) {
		log.Printf("[signal] RequestRelay from %s for invalid target id %q", raddr, targetID)
		s.sendUDP(targetOfflineRelayResponse(relayServer), raddr)
		return
	}

	log.Printf("[signal] RequestRelay from %s for target %s (uuid=%q, secure=%v, connType=%v)", raddr, targetID, relayUUID, msg.Secure, msg.ConnType)

	initiatorID, ok := s.requireAuthorizedInitiator(raddr, targetID, msg.GetToken(), 0)
	if !ok {
		s.sendUDP(s.relayUnauthorizedResponse(relayServer), raddr)
		return
	}
	policy := s.sessionPolicy(msg.GetToken(), raddr, false, msg.GetConnType())
	s.limitToQuickSupport(&policy, targetID, msg.GetConnType())
	if policy.refusal != "" {
		s.refuseForFeature(raddr, initiatorID, targetID, policy)
		s.sendUDP(relayRefusedResponse(policy.refusal, relayServer), raddr)
		return
	}
	s.logAuthorizedInitiator(raddr, initiatorID, targetID, msg.GetToken(), "request_relay")
	permissions := policy.permissions

	target := s.peers.Get(targetID)

	if target == nil || !target.Reachable(config.RegTimeout) {
		// Target offline — send relay response with failure
		resp := &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_RelayResponse{
				RelayResponse: &pb.RelayResponse{
					RefuseReason: refuseTargetOffline,
					RelayServer:  relayServer,
				},
			},
		}
		s.sendUDP(resp, raddr)
		return
	}

	// Reject disabled, banned, or soft-deleted targets as offline.
	if target.Banned || !s.targetAcceptsInboundSession(targetID) {
		log.Printf("[signal] RequestRelay: target %s is unavailable, rejecting", targetID)
		resp := &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_RelayResponse{
				RelayResponse: &pb.RelayResponse{
					RefuseReason: refuseTargetOffline,
					RelayServer:  relayServer,
				},
			},
		}
		s.sendUDP(resp, raddr)
		return
	}

	// LAN detection: use server's LAN IP only for genuine LAN cases. Shared
	// public IP peers keep the public relay to avoid NAT hairpin failures.
	route := s.chooseRelay(relayRouteRequest{
		base: relayServer, a: raddr, b: target.UDPAddr, target: target,
		policyPeers: []string{initiatorID, targetID},
	})
	if refuse := s.admitSession(route.Tickets, relayUUID, initiatorID, targetID, policy.account, policy.consoleSession); refuse != "" {
		s.sendUDP(relayRefusedResponse(refuse, relayServer), raddr)
		return
	}
	relayServer, sameNetwork, hairpin := route.Addr, route.SameNetwork, route.Hairpin
	if sameNetwork {
		log.Printf("[signal] RequestRelay LAN detected: %s and %s on same network, relay=%s", raddr.IP, target.UDPAddr.IP, relayServer)
	}
	if hairpin {
		log.Printf("[signal] RequestRelay shared public IP %s detected (NAT hairpin) → keeping public relay=%s", raddr.IP, relayServer)
	}

	s.recordConnectionSession(raddr, initiatorID, targetID, msg.GetToken(), "request_relay", relayUUID)

	// Forward relay request to target peer (supports UDP, TCP, and WebSocket targets).
	// NOTE: Must use RequestRelay type, not RelayResponse — RustDesk client's
	// handle_resp() dispatches RequestRelay to create_relay() but drops RelayResponse.
	// control_permissions are the server's (sessionPermissions), never the
	// controller's: the device applies them over its own settings. The
	// controller's token is its sign-in and stays here.
	relayReq := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RequestRelay{
			RequestRelay: &pb.RequestRelay{
				SocketAddr: crypto.EncodeAddr(raddr),
				Uuid:       relayUUID,
				Id:         msg.Id,
				// Target validates this against its own relay (see
				// relayAdvertisedToTarget); prefer what it reported.
				RelayServer:        route.TargetAddr,
				ControlledContext:  msg.ControlledContext,
				SwitchCode:         msg.SwitchCode,
				Secure:             msg.Secure,
				ConnType:           msg.ConnType,
				ControlPermissions: permissions,
			},
		},
	}

	// Store the UUID so we can recover it if target responds with empty UUID.
	s.storePendingUUID(targetID, raddr, relayUUID, initiatorID)
	s.sendToPeer(targetID, relayReq)

	// Sign the target's PK for E2E encryption verification
	var signedPk []byte
	targetPK := s.peerPublicKey(targetID, target)
	if len(targetPK) > 0 {
		signed, err := s.kp.SignIdPk(targetID, targetPK)
		if err != nil {
			log.Printf("[signal] Failed to sign PK for %s: %v", targetID, err)
		} else {
			signedPk = signed
			log.Printf("[signal] Signed PK for relay to %s: %d bytes", targetID, len(signedPk))
		}
	}

	// Confirm to initiator with SIGNED public key
	log.Printf("[signal] RequestRelay (UDP): returning RelayResponse to initiator %s (uuid=%q, relay=%q)", raddr, relayUUIDShort(relayUUID), relayServer)
	resp := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				SocketAddr:  encodeRelayResponsePeerSocketAddr(target),
				Uuid:        relayUUID,
				RelayServer: relayServer,
				Union:       &pb.RelayResponse_Pk{Pk: signedPk},
			},
		},
	}
	s.sendUDP(resp, raddr)
}

// handleRequestRelayTCP handles relay setup request over TCP/WS.
//
// Matching the UDP handler behavior: forwards RequestRelay to the target via UDP
// AND sends an immediate RelayResponse to the TCP initiator with the target's
// signed PK, relay server, and UUID.  This ensures the initiator can proceed
// with the relay connection immediately without waiting for the target's response.
//
// Previous behavior (sending nothing back and waiting for the target's
// RelayResponse) caused timeouts for TCP signaling clients (e.g. logged-in users).
//
// initiatorHint is ConnTCP for native TCP signal or ConnWS for WebSocket Mode.
// The active connection is authoritative: a peer may retain a stale
// registration type while a new WebSocket session is already handling this
// request.
func (s *Server) handleRequestRelayTCP(msg *pb.RequestRelay, raddr *net.UDPAddr, initiatorHint peer.ConnType) *pb.RendezvousMessage {
	return s.requestRelayTCP(msg, raddr, initiatorHint, false)
}

// requestRelayTCP is handleRequestRelayTCP; panel is true on the
// connection of the panel's web client.
func (s *Server) requestRelayTCP(msg *pb.RequestRelay, raddr *net.UDPAddr, initiatorHint peer.ConnType, panel bool) *pb.RendezvousMessage {
	if raddr == nil {
		log.Printf("[signal] RequestRelay (TCP): nil address, ignoring")
		return nil
	}
	targetID := msg.Id

	// Generate UUID if the client sent an empty one (see handleRequestRelay comment).
	relayUUID := msg.Uuid
	if relayUUID == "" {
		relayUUID = uuid.New().String()
		log.Printf("[signal] RequestRelay (TCP): client %s sent empty UUID, generated %s", raddr, relayUUIDShort(relayUUID))
	}

	relayServer := s.sanitizeClientRelayAddress(msg.RelayServer)
	if !isValidPeerID(targetID) {
		log.Printf("[signal] RequestRelay (TCP) from %s for invalid target id %q", raddr, targetID)
		return targetOfflineRelayResponse(relayServer)
	}

	log.Printf("[signal] RequestRelay (TCP) from %s for target %s (uuid=%q, secure=%v, connType=%v)", raddr, targetID, relayUUID, msg.Secure, msg.ConnType)

	initiatorID, ok := s.authorizeInitiator(raddr, targetID, msg.GetToken(), 0, panel)
	if !ok {
		return s.relayUnauthorizedResponse(relayServer)
	}
	policy := s.sessionPolicy(msg.GetToken(), raddr, panel, msg.GetConnType())
	s.limitToQuickSupport(&policy, targetID, msg.GetConnType())
	if policy.refusal != "" {
		s.refuseForFeature(raddr, initiatorID, targetID, policy)
		return relayRefusedResponse(policy.refusal, relayServer)
	}
	s.logAuthorizedInitiator(raddr, initiatorID, targetID, msg.GetToken(), "request_relay")
	permissions := policy.permissions

	target := s.peers.Get(targetID)

	if target == nil || !target.Reachable(config.RegTimeout) {
		log.Printf("[signal] RequestRelay (TCP): target %s offline", targetID)
		return &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_RelayResponse{
				RelayResponse: &pb.RelayResponse{
					RefuseReason: refuseTargetOffline,
					RelayServer:  relayServer,
				},
			},
		}
	}

	// Reject disabled, banned, or soft-deleted targets as offline.
	if target.Banned || !s.targetAcceptsInboundSession(targetID) {
		log.Printf("[signal] RequestRelay (TCP): target %s is unavailable, rejecting", targetID)
		return &pb.RendezvousMessage{
			Union: &pb.RendezvousMessage_RelayResponse{
				RelayResponse: &pb.RelayResponse{
					RefuseReason: refuseTargetOffline,
					RelayServer:  relayServer,
				},
			},
		}
	}

	// The relay bridges mixed WebSocket/native framing. Keep this
	// information for relay address selection and diagnostics, but do not
	// refuse the pair here.
	initiatorType := initiatorHint
	if initiatorHint != peer.ConnWS {
		if initiator := s.peers.Get(initiatorID); initiator != nil {
			initiatorType = initiator.ConnType
		}
	}
	if relayTransportMismatch(initiatorType, target.ConnType) {
		log.Printf("[signal] RequestRelay (TCP): mixed transport initiator=%s target=%s (%s vs %s) — relay will bridge framing",
			initiatorID, targetID, initiatorType, target.ConnType)
	}
	// LAN detection: use server's LAN IP only for genuine LAN cases. Shared
	// public IP peers keep the public relay to avoid NAT hairpin failures.
	// Only applicable when target has a known UDP address for comparison.
	route := s.chooseRelay(relayRouteRequest{
		base: relayServer, a: raddr, b: target.UDPAddr, target: target,
	})
	if refuse := s.admitSession(route.Tickets, relayUUID, initiatorID, targetID, policy.account, policy.consoleSession); refuse != "" {
		return relayRefusedResponse(refuse, relayServer)
	}

	s.recordConnectionSession(raddr, initiatorID, targetID, msg.GetToken(), "request_relay", relayUUID)

	relayServer, sameNetwork, hairpin := route.Addr, route.SameNetwork, route.Hairpin
	if sameNetwork {
		log.Printf("[signal] RequestRelay (TCP) LAN detected: %s and %s on same network, relay=%s", raddr.IP, target.UDPAddr.IP, relayServer)
	} else if hairpin {
		log.Printf("[signal] RequestRelay (TCP) shared public IP %s detected (NAT hairpin) → keeping public relay=%s", raddr.IP, relayServer)
	} else {
		// Debug: log why LAN detection failed
		if target.UDPAddr == nil {
			log.Printf("[signal] RequestRelay (TCP) LAN check skipped: target %s has no UDPAddr (connType=%s)", targetID, target.ConnType)
		} else {
			log.Printf("[signal] RequestRelay (TCP) LAN check failed: initiator=%s target=%s (isSameNetwork=false)", raddr, target.UDPAddr)
		}
	}

	advertisedAddr := relayAdvertisedAddr(s, raddr, initiatorID, initiatorType)
	if advertisedAddr == nil {
		return s.relayUnauthorizedResponse(relayServer)
	}
	if !advertisedAddr.IP.Equal(raddr.IP) || advertisedAddr.Port != raddr.Port {
		log.Printf("[signal] RequestRelay (TCP): advertising %s for initiator %s (correlation=%s)",
			advertisedAddr, initiatorID, raddr)
	}

	// Forward RequestRelay to target peer (supports UDP, TCP, and WebSocket targets).
	// control_permissions and the token as in handleRequestRelay.
	reqRelay := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RequestRelay{
			RequestRelay: &pb.RequestRelay{
				SocketAddr: crypto.EncodeAddr(advertisedAddr),
				Uuid:       relayUUID,
				Id:         msg.Id,
				// The target validates this against the relay it configured and
				// silently drops a mismatch, so prefer the endpoint the target
				// itself reported before falling back to the server's value.
				RelayServer:        route.TargetAddr,
				ControlledContext:  msg.ControlledContext,
				SwitchCode:         msg.SwitchCode,
				Secure:             msg.Secure,
				ConnType:           msg.ConnType,
				ControlPermissions: permissions,
			},
		},
	}
	// Store the UUID so we can recover it if target responds with empty UUID.
	s.storePendingRelay(targetID, raddr, advertisedAddr, relayUUID, initiatorID)
	if s.sendToPeer(targetID, reqRelay) {
		log.Printf("[signal] RequestRelay (TCP): forwarded to %s (connType=%s) secure=%v relay_to_target=%s",
			targetID, target.ConnType, msg.Secure, reqRelay.GetRequestRelay().GetRelayServer())
	}

	// Sign the target's PK for E2E encryption verification
	var signedPk []byte
	targetPK := s.peerPublicKey(targetID, target)
	if len(targetPK) > 0 {
		signed, err := s.kp.SignIdPk(targetID, targetPK)
		if err != nil {
			log.Printf("[signal] RequestRelay (TCP): failed to sign PK for %s: %v", targetID, err)
		} else {
			signedPk = signed
			log.Printf("[signal] RequestRelay (TCP): signed PK for %s (%d bytes)", targetID, len(signedPk))
		}
	}

	// Immediate RelayResponse to the initiator.
	//
	// Upstream hbbs relies on the target's RelayResponse instead, but this code
	// path is relied on by working peers in production (188.137.83.41 pairs
	// repeatedly) and by the whole existing test suite, so the initiator keeps
	// its prompt answer.
	//
	// The UUID divergence is handled where it actually matters: a target that
	// answers with a different UUID is correlated through the pending entry
	// stored above, so both sides still reach hbbr and pair.
	log.Printf("[signal] RequestRelay (TCP): returning RelayResponse to initiator %s (uuid=%q, relay=%q)", raddr, relayUUIDShort(relayUUID), relayServer)
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				SocketAddr:  encodeRelayResponsePeerSocketAddr(target),
				Uuid:        relayUUID,
				RelayServer: relayServer,
				Union:       &pb.RelayResponse_Pk{Pk: signedPk},
			},
		},
	}
}

// handleRelayResponseForward forwards a RelayResponse from the target peer to
// the initiator.  The target sends this after receiving PunchHole/RequestRelay
// via UDP: it generates a relay UUID, connects to the relay server, and sends
// RelayResponse to the signal server (TCP) with socket_addr = initiator's
// address.
//
// senderAddr is the address of the TCP connection that sent this RelayResponse
// (the target peer). Used for IP-based PK lookup when the id field is empty.
//
// Following the Rust hbbs behavior:
// 1. Decode socket_addr to get initiator's address (addr_b in Rust)
// 2. Clear socket_addr (initiator doesn't need it)
// 3. Resolve target's PK from id field
// 4. Set pk field (initiator needs this)
// 5. Adjust relay_server if needed
// 6. Forward to initiator via their stored TCP connection (tcpPunchConns)
func (s *Server) handleRelayResponseForward(msg *pb.RendezvousMessage, senderAddr *net.UDPAddr) {
	connection := s.cfg.ConnectionSettings()
	rr := msg.GetRelayResponse()
	if rr == nil || len(rr.SocketAddr) == 0 {
		return
	}

	initiatorAddr, err := crypto.DecodeAddr(rr.SocketAddr)
	if err != nil {
		log.Printf("[signal] RelayResponse forward: cannot decode socket_addr: %v", err)
		return
	}

	// Look up the target peer to get its public key and sign it (matching Rust's get_pk).
	targetID := rr.GetId()
	senderID := s.peerIDForAddr(senderAddr)
	if targetID != "" && senderID != "" && targetID != senderID {
		log.Printf("[signal] RelayResponse forward: refusing target=%q from registered peer=%q", targetID, senderID)
		return
	}
	if targetID != "" && senderID == "" && !s.relayResponseSourceMatchesTarget(targetID, senderAddr) {
		log.Printf("[signal] RelayResponse forward: refusing target=%q from unexpected source=%s", targetID, senderAddr)
		return
	}

	// Prefer pending-session correlation over FindByIP on shared NAT.
	var pending *pendingUUID
	if rr.Uuid != "" {
		pending = s.getPendingRelayByUUID(rr.Uuid)
	}
	if pending == nil && targetID != "" {
		pending = s.getPendingRelay(targetID, initiatorAddr)
	}
	if pending == nil {
		pending = s.getPendingRelayByAdvertised(targetID, initiatorAddr)
	}
	if pending == nil && targetID == "" && initiatorAddr != nil {
		suffix := "\x00" + normalizeAddrKey(initiatorAddr.String())
		s.pendingRelayUUIDs.Range(func(key, value any) bool {
			pu, ok := value.(*pendingUUID)
			if !ok || pu == nil {
				return true
			}
			keyStr, _ := key.(string)
			if strings.HasSuffix(keyStr, suffix) || pu.advertisedAddr == normalizeAddrKey(initiatorAddr.String()) {
				pending = pu
				return false
			}
			return true
		})
	}
	if pending != nil {
		if targetID == "" && pending.targetID != "" {
			targetID = pending.targetID
			log.Printf("[signal] RelayResponse forward: resolved empty target id via pending session → %s", targetID)
		}
		if rr.Uuid == "" && pending.uuid != "" {
			rr.Uuid = pending.uuid
			log.Printf("[signal] RelayResponse from %s has empty UUID — recovered original %s from pending store", senderAddr, relayUUIDShort(pending.uuid))
		}
	}

	forwardAddr := initiatorAddr
	if pending != nil && pending.correlationAddr != "" {
		if addr, resolveErr := net.ResolveUDPAddr("udp", pending.correlationAddr); resolveErr == nil {
			forwardAddr = addr
		}
	}

	// Fallback: if id field is empty (common with some RustDesk client versions),
	// identify the sender by exact address / TCP session, then safe single-IP only.
	if targetID == "" && senderAddr != nil {
		if senderID != "" {
			targetID = senderID
			log.Printf("[signal] RelayResponse forward: resolved sender %s to registered peer %s", senderAddr, targetID)
		} else if n := s.peers.CountByIP(senderAddr.IP); n > 1 {
			log.Printf("[signal] RelayResponse forward: ambiguous IP lookup for %s (%d peers) — cannot resolve empty id", senderAddr.IP, n)
		} else if entry := s.peers.FindByIP(senderAddr.IP); entry != nil {
			targetID = entry.ID
			log.Printf("[signal] RelayResponse forward: resolved sender %s to peer %s via IP lookup", senderAddr, targetID)
		}
	}

	// If the target sent a RelayResponse with an empty UUID, try to recover the
	// original UUID that we sent to the target in RequestRelay/PunchHole. This
	// is critical for relay pairing — the target may have connected to relay with
	// that UUID, but the old RustDesk client doesn't echo it back.
	if rr.Uuid == "" {
		storedUUID := ""
		if pending != nil {
			storedUUID = pending.uuid
		}
		if storedUUID == "" {
			storedUUID = s.getPendingUUID(targetID, initiatorAddr)
		}
		if storedUUID != "" {
			rr.Uuid = storedUUID
			log.Printf("[signal] RelayResponse from %s has empty UUID — recovered original %s from pending store", senderAddr, relayUUIDShort(storedUUID))
		} else {
			// Last resort: generate a new UUID. This will likely fail relay pairing
			// because target already connected with different (empty?) UUID.
			rr.Uuid = uuid.New().String()
			log.Printf("[signal] WARNING: RelayResponse from %s has empty UUID and no pending UUID found — generated %s (relay pairing may fail)", senderAddr, relayUUIDShort(rr.Uuid))
		}
	}

	// Resolve the initiator so we can mint a relay ticket before advertising the
	// UUID. Without this, P2P→relay fallback forwards a RelayResponse that the
	// hardened relay rejects as "Unauthorized relay UUID". Prefer pending
	// / exact addr / panel proxy / shared-NAT flag — never multi-peer FindByIP.
	initiatorID := ""
	// The account behind the punch request goes on the ticket, as at
	// RequestRelay: the desktop app's client token, or the web client's
	// proof (also read from its connection below)
	var account int64
	consoleSession := ""
	if pending != nil {
		initiatorID = pending.initiatorID
		account, consoleSession = pending.account, pending.consoleSession
	}
	if initiatorID == "" {
		initiatorID = s.peerIDForAddr(initiatorAddr)
	}
	if initiatorID == "" && s.isPanelConnAddr(initiatorAddr) {
		initiatorID = panelWebRemoteInitiatorID
		log.Printf("[signal] RelayResponse forward: initiator %s is the console's web client", initiatorAddr)
	}
	if initiatorID == "" && initiatorAddr != nil && connection.AllowSharedNATInitiator &&
		s.peers != nil && s.peers.CountByIP(initiatorAddr.IP) > 1 {
		initiatorID = sharedNATInitiatorID
		log.Printf("[signal] RelayResponse forward: shared-NAT initiator %s authorized as %s", initiatorAddr, sharedNATInitiatorID)
	}
	if initiatorID == "" && initiatorAddr != nil {
		if n := s.peers.CountByIP(initiatorAddr.IP); n > 1 {
			log.Printf("[signal] RelayResponse forward: ambiguous initiator IP lookup for %s (%d peers)", initiatorAddr.IP, n)
		} else if entry := s.peers.FindByIP(initiatorAddr.IP); entry != nil {
			initiatorID = entry.ID
			log.Printf("[signal] RelayResponse forward: resolved initiator %s to peer %s via IP lookup", initiatorAddr, initiatorID)
		}
	}
	if account == 0 || pending == nil || initiatorID != pending.initiatorID {
		account, consoleSession = s.panelAccount(initiatorAddr), s.panelSession(initiatorAddr)
	}
	if targetID == "" || initiatorID == "" {
		log.Printf("[signal] RelayResponse forward: refusing uuid=%q — unresolved pair (initiator=%q target=%q sender=%s)",
			rr.Uuid, initiatorID, targetID, senderAddr)
		return
	}
	// A session the signal server admitted already (the console's web
	// client gets its ticket from RequestRelay and closes its socket before
	// the device answers): admitting it again would name no account, which
	// the registry refuses, and register it with billing a second time
	// LAN detection: use LAN relay only for genuine LAN cases. Shared public IP
	// peers keep the public relay to avoid NAT hairpin failures.
	route := s.chooseRelay(relayRouteRequest{base: s.getRelayServer(), a: senderAddr, b: initiatorAddr})
	if route.Tickets.Admitted(rr.Uuid, initiatorID, targetID) {
		log.Printf("[signal] RelayResponse forward: uuid=%q initiator=%q target=%q was admitted already", rr.Uuid, initiatorID, targetID)
	} else if refuse := s.admitSession(route.Tickets, rr.Uuid, initiatorID, targetID, account, consoleSession); refuse != "" {
		log.Printf("[signal] RelayResponse forward: %s (uuid=%q initiator=%q target=%q) — not forwarding",
			refuse, rr.Uuid, initiatorID, targetID)
		return
	}

	var signedPk []byte
	target := s.peers.Get(targetID)
	targetPK := s.peerPublicKey(targetID, target)
	if target != nil && len(targetPK) > 0 {
		// Sign the PK with server's Ed25519 key (enables client E2E verification)
		signed, err := s.kp.SignIdPk(targetID, targetPK)
		if err != nil {
			log.Printf("[signal] Failed to sign PK for %s in RelayResponse: %v", targetID, err)
		} else {
			signedPk = signed
			log.Printf("[signal] Signed PK for %s in RelayResponse: %d bytes", targetID, len(signedPk))
		}
	}

	if len(signedPk) == 0 {
		log.Printf("[signal] WARNING: RelayResponse forward — no PK available for target %q (sender=%s)", targetID, senderAddr)
	}

	// The incoming socket_addr routes the response back to the initiator and
	// must not be forwarded as-is. Replace it with the target's server-derived
	// compatibility address so clients can decode the remote peer metadata
	// without receiving the initiator's routing address.
	rr.SocketAddr = encodeRelayResponsePeerSocketAddr(target)
	rr.SocketAddrV6 = nil

	relayServer, sameNetwork, hairpin := route.Addr, route.SameNetwork, route.Hairpin
	if sameNetwork {
		log.Printf("[signal] RelayResponse LAN detected: %s and %s on same network, relay=%s", senderAddr.IP, initiatorAddr.IP, relayServer)
	}
	if hairpin && senderAddr != nil {
		log.Printf("[signal] RelayResponse shared public IP %s detected (NAT hairpin) → keeping public relay=%s", senderAddr.IP, relayServer)
	}
	rr.RelayServer = relayServer

	// Replace union: id → SIGNED pk (initiator needs target's signed public key)
	rr.Union = &pb.RelayResponse_Pk{Pk: signedPk}

	initiatorResp := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: rr,
		},
	}

	// Primary delivery: TCP punch map or WebSocket peer.
	forwardAddrStr := normalizeAddrKey(forwardAddr.String())
	if s.forwardToInitiator(forwardAddrStr, initiatorResp) {
		log.Printf("[signal] RelayResponse forwarded to %s (advertised=%s, uuid=%q, relay=%s, signedPk=%d bytes)",
			forwardAddrStr, initiatorAddr, rr.Uuid, relayServer, len(signedPk))
		return
	}

	// Safe UDP fallback: exact initiator endpoint, or the resolved initiator's
	// registered UDP addr. Never FindByIP on shared NAT: it could deliver to the wrong peer.
	if forwardAddr != nil {
		if s.sendUDP(initiatorResp, forwardAddr) {
			log.Printf("[signal] RelayResponse forwarded to exact initiator %s via UDP (advertised=%s, uuid=%q, relay=%s, signedPk=%d bytes)",
				forwardAddr, initiatorAddr, rr.Uuid, relayServer, len(signedPk))
			return
		}
	}
	if entry := s.peers.Get(initiatorID); entry != nil && entry.UDPAddr != nil {
		if s.peers.CountByIP(entry.UDPAddr.IP) > 1 &&
			(forwardAddr == nil || entry.UDPAddr.Port != forwardAddr.Port || !entry.UDPAddr.IP.Equal(forwardAddr.IP)) {
			log.Printf("[signal] RelayResponse: refusing ambiguous UDP delivery for initiator %s at shared IP %s (uuid=%q)", initiatorID, entry.UDPAddr.IP, rr.Uuid)
			return
		}
		if s.sendUDP(initiatorResp, entry.UDPAddr) {
			log.Printf("[signal] RelayResponse forwarded to peer %s at %s via UDP (uuid=%q, relay=%s, signedPk=%d bytes)", entry.ID, entry.UDPAddr, rr.Uuid, relayServer, len(signedPk))
			return
		}
	}

	log.Printf("[signal] RelayResponse: cannot deliver to %s (advertised=%s, no TCP conn, no safe peer match, uuid=%q)",
		forwardAddrStr, initiatorAddr, rr.Uuid)
}

// senderSpeaksForPeer reports whether senderAddr may speak for targetID:
// an address bound to another peer may not, and the IP must be the target's
// registered one.
func (s *Server) senderSpeaksForPeer(targetID string, senderAddr *net.UDPAddr) bool {
	if targetID == "" || senderAddr == nil {
		return false
	}
	if senderID := s.peerIDForAddr(senderAddr); senderID != "" && senderID != targetID {
		return false
	}
	return s.relayResponseSourceMatchesTarget(targetID, senderAddr)
}

// relayResponseSourceMatchesTarget applies the strongest source correlation
// available for legacy clients whose response has no registered TCP identity.
// It deliberately checks the observed public IP only; an IP-only match is not
// treated as a credential and ambiguous same-NAT cases remain rejected above.
func (s *Server) relayResponseSourceMatchesTarget(targetID string, senderAddr *net.UDPAddr) bool {
	if s == nil || s.peers == nil || senderAddr == nil || senderAddr.IP == nil {
		return false
	}
	target := s.peers.Get(targetID)
	if target == nil {
		return false
	}
	if target.UDPAddr != nil && target.UDPAddr.IP != nil {
		return target.UDPAddr.IP.Equal(senderAddr.IP)
	}
	host, _, err := net.SplitHostPort(target.IP)
	if err != nil {
		host = target.IP
	}
	targetIP := net.ParseIP(host)
	return targetIP != nil && targetIP.Equal(senderAddr.IP)
}

// logClientFetchLocalAddr notes a FetchLocalAddr sent by a client. Only the
// server sends FetchLocalAddr (to the target of a LAN punch); one from a
// client would make the server send the client's text to an address of its
// choice, so it is dropped.
func logClientFetchLocalAddr(transport, remote string) {
	log.Printf("[signal] %s FetchLocalAddr from client %q dropped: only the server sends it", transport, remote)
}

// handleLocalAddr completes the FetchLocalAddr→LocalAddr exchange and returns
// the target's actual LAN listener inside a PunchHoleResponse.
func (s *Server) handleLocalAddr(msg *pb.LocalAddr, raddr *net.UDPAddr) {
	s.completeLANAddr(msg, raddr)
}

// relayAdvertisedToTarget returns the relay endpoint to put in a RequestRelay
// sent to target.
//
// A RustDesk peer validates the incoming relay against its own configured value
// with check_port(addr, RELAY_PORT) and silently drops any mismatch ("relay
// server ... was not offered by this peer").
//
// So the peer's own value wins when we know it. When we do not, send the bare
// host for a relay on RELAY_PORT (21117): check_port() normalises both sides
// to RELAY_PORT, so a portless value matches a client configured as either
// `host` or `host:21117`. Production confirms this shape pairs — the peer that
// repeatedly established sessions reported `85.14.70.12` with no port, while
// the one we sent `85.14.70.12:21117` to never answered. A relay on another
// port keeps it: check_port() would add 21117 to the bare host and the peer
// would dial a port where no relay of this server listens.
func relayAdvertisedToTarget(target *peer.Entry, fallback string) string {
	if target != nil {
		if reported := strings.TrimSpace(target.RelayServer); reported != "" {
			return reported
		}
	}
	if host, port, err := net.SplitHostPort(fallback); err == nil && host != "" && port == clientRelayPort {
		return host
	}
	return fallback
}

// clientRelayPort is RELAY_PORT of RustDesk clients, the port check_port()
// adds to a relay address without one.
const clientRelayPort = "21117"

// handleIceCandidate relays a WebRTC trickle-ICE candidate from one peer to
// another. Recent RustDesk clients exchange candidates through the rendezvous
// server while negotiating a WebRTC transport; dropping them (the union member
// did not exist before) leaves two new peers unable to complete negotiation.
//
// IceCandidate carries the destination peer id in `id` and the sender's
// session key. It is forwarded only between the two ends of a punch the
// server signalled (the offer travels in PunchHoleRequest), so a stranger
// cannot send candidates to any online peer. Unknown or offline targets are
// ignored: candidates are advisory and trickle may continue.
func (s *Server) handleIceCandidate(msg *pb.IceCandidate, senderAddr *net.UDPAddr) {
	if msg == nil {
		return
	}
	targetID := strings.TrimSpace(msg.Id)
	if targetID == "" {
		log.Printf("[signal] IceCandidate without target id ignored")
		return
	}
	if !s.iceCandidateAllowed(targetID, senderAddr) {
		log.Printf("[signal] IceCandidate for %q from %s dropped: no punch between them pending", targetID, senderAddr)
		return
	}
	target := s.peers.Get(targetID)
	if target == nil || !target.Reachable(config.RegTimeout) {
		return
	}
	fwd := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_IceCandidate{
			IceCandidate: msg,
		},
	}
	if !s.sendToPeer(targetID, fwd) && target.UDPAddr != nil {
		s.sendUDP(fwd, target.UDPAddr)
	}
}

// iceCandidateAllowed reports whether senderAddr is the initiator of a
// pending punch to destID, or speaks for the target of a pending punch whose
// initiator is destID (like PunchHoleSent, possibly from a new socket).
func (s *Server) iceCandidateAllowed(destID string, senderAddr *net.UDPAddr) bool {
	if senderAddr == nil {
		return false
	}
	if s.getPendingRelay(destID, senderAddr) != nil {
		return true
	}
	allowed := false
	s.pendingRelayUUIDs.Range(func(_, value any) bool {
		if pu, ok := value.(*pendingUUID); ok && pu != nil && pu.initiatorID == destID && s.senderSpeaksForPeer(pu.targetID, senderAddr) {
			allowed = true
			return false
		}
		return true
	})
	return allowed
}

// handleTestNat handles NAT type detection (TCP port 21115).
// M8: Also sends ConfigUpdate with relay/rendezvous server info for clients ≥1.3.x.
func (s *Server) handleTestNat(msg *pb.TestNatRequest, raddr net.Addr) *pb.RendezvousMessage {
	// Extract the source port from the remote address
	tcpAddr, ok := raddr.(*net.TCPAddr)
	if !ok {
		return nil
	}

	resp := &pb.TestNatResponse{
		Port: int32(tcpAddr.Port),
	}

	// M8: advertise the rendezvous (ID) servers so clients ≥1.3.x can learn
	// about dynamic reconfiguration.
	//
	// SECURITY/CORRECTNESS: this list must never contain relay addresses.
	// ConfigUpdate.rendezvous_servers tells the client which ID server to use;
	// filling it from GetRelayServers() made newer clients reconnect their
	// signal socket to the relay port, stop answering punch/relay requests and
	// fail every session with a relay pair timeout.
	rendezvousServers := s.cfg.GetRendezvousServers()
	if len(rendezvousServers) > 0 {
		resp.Cu = &pb.ConfigUpdate{
			Serial:            msg.Serial + 1,
			RendezvousServers: rendezvousServers,
		}
	}

	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_TestNatResponse{
			TestNatResponse: resp,
		},
	}
}

// splitAndTrim splits a comma-separated string and trims whitespace from each element.
func splitAndTrim(s string) []string {
	parts := make([]string, 0)
	for _, p := range regexp.MustCompile(`\s*,\s*`).Split(s, -1) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// maxOnlineRequestPeers caps the ids one OnlineRequest is answered for; the
// answer covers the first ones.
const maxOnlineRequestPeers = 10000

// handleOnlineRequest checks which peers are online (TCP port 21115).
func (s *Server) handleOnlineRequest(msg *pb.OnlineRequest) *pb.RendezvousMessage {
	ids := msg.Peers
	if len(ids) > maxOnlineRequestPeers {
		ids = ids[:maxOnlineRequestPeers]
	}
	states := s.peers.OnlineStates(ids, config.RegTimeout)
	// A retained pending transport is only an internal bridge for the
	// approval transition. Do not advertise it as online to other clients.
	if pending := s.pendingEnrollmentIDs(states); len(pending) > 0 {
		for i, id := range ids {
			if _, ok := pending[id]; ok {
				states[i/8] &^= 1 << uint(7-(i%8))
			}
		}
	}

	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_OnlineResponse{
			OnlineResponse: &pb.OnlineResponse{
				States: states,
			},
		},
	}
}

// sendRelayResponse sends relay-only response to the initiator when direct connection is skipped.
// The target's public key is signed with the server's Ed25519 key (NaCl combined format)
// so the initiator can verify the target's identity for E2E encryption.
// The target's RequestRelay carries permissions (sessionPermissions).
func (s *Server) sendRelayResponse(target *peer.Entry, raddr *net.UDPAddr, msg *pb.PunchHoleRequest, route RelayRoute, initiatorID string, policy sessionPolicy) {
	permissions := policy.permissions
	relay := route.Addr
	// Generate a relay session UUID for pairing both peers at hbbr.
	relayUUID := uuid.New().String()
	if refuse := s.admitSession(route.Tickets, relayUUID, initiatorID, target.ID, policy.account, policy.consoleSession); refuse != "" {
		s.sendUDP(relayRefusedResponse(refuse, relay), raddr)
		return
	}
	// RustDesk 1.5.3 validates the relay in the target-bound RequestRelay
	// against the relay address that target previously reported (#16858).
	// Keep the initiator's reachable server-selected relay separate from the
	// target's peer-offered value; sending the former to the target can make
	// newer clients silently drop the request and leave a relay timeout.
	targetRelay := route.TargetAddr

	// Sign the target's PK with server's Ed25519 key for E2E verification.
	// Format: [64-byte Ed25519 signature][serialized IdPk protobuf] — NaCl combined mode.
	// Without signing, clients cannot verify target identity and E2E will fail.
	var signedPk []byte
	targetPK := s.peerPublicKey(target.ID, target)
	if len(targetPK) > 0 {
		signed, err := s.kp.SignIdPk(target.ID, targetPK)
		if err != nil {
			log.Printf("[signal] sendRelayResponse: failed to sign PK for %s: %v", target.ID, err)
		} else {
			signedPk = signed
			log.Printf("[signal] sendRelayResponse: signed PK for %s (%d bytes)", target.ID, len(signedPk))
		}
	}

	// Send RelayResponse (NOT PunchHoleResponse) to the initiator.
	// RelayResponse contains the UUID field required by hbbr for session pairing.
	// PunchHoleResponse does not have a uuid field, so clients would send
	// RequestRelay with an empty UUID, causing hbbr to reject the connection.
	resp := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				Uuid:        relayUUID,
				RelayServer: relay,
				Union:       &pb.RelayResponse_Pk{Pk: signedPk},
			},
		},
	}
	s.sendUDP(resp, raddr)

	// Forward RequestRelay to the target so it connects to hbbr with the same UUID.
	reqRelay := &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RequestRelay{
			RequestRelay: &pb.RequestRelay{
				Id:                 msg.Id,
				Uuid:               relayUUID,
				SocketAddr:         crypto.EncodeAddr(raddr),
				RelayServer:        targetRelay,
				Secure:             false,
				ConnType:           msg.ConnType,
				ControlPermissions: permissions,
			},
		},
	}
	if target.UDPAddr != nil {
		// Store the UUID so we can recover it if target responds with empty UUID.
		s.storePendingUUID(target.ID, raddr, relayUUID, initiatorID)
		s.sendUDP(reqRelay, target.UDPAddr)
		log.Printf("[signal] sendRelayResponse: forwarded RequestRelay to target %s at %s (uuid=%s relay_to_initiator=%s relay_to_target=%s)",
			target.ID, target.UDPAddr, relayUUIDShort(relayUUID), relay, targetRelay)
	}
}

func (s *Server) peerIDForAddr(raddr *net.UDPAddr) string {
	if raddr == nil || s.peers == nil {
		return ""
	}
	if p := s.peers.FindByAddr(raddr); p != nil {
		return p.ID
	}
	if id := s.tcpSessionPeerID(raddr); id != "" {
		return id
	}
	return ""
}

// punchHoleUnauthorizedResponse refuses outbound PunchHole when the initiator
// is not an authorized peer.
func (s *Server) punchHoleUnauthorizedResponse() *pb.RendezvousMessage {
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_PunchHoleResponse{
			PunchHoleResponse: &pb.PunchHoleResponse{
				Failure: pb.PunchHoleResponse_ID_NOT_EXIST,
			},
		},
	}
}

// relayUnauthorizedResponse refuses outbound RequestRelay when the initiator
// is not an authorized peer.
func (s *Server) relayUnauthorizedResponse(relayServer string) *pb.RendezvousMessage {
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				RefuseReason: refuseInitiatorNotAuthorized,
				RelayServer:  relayServer,
			},
		},
	}
}

// targetOfflineRelayResponse refuses a RequestRelay whose target cannot be
// reached.
func targetOfflineRelayResponse(relayServer string) *pb.RendezvousMessage {
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				RefuseReason: refuseTargetOffline,
				RelayServer:  relayServer,
			},
		},
	}
}

// punchHoleOfflineResponse answers a punch to a target that may not be
// reached as if it were offline.
func punchHoleOfflineResponse() *pb.RendezvousMessage {
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_PunchHoleResponse{
			PunchHoleResponse: &pb.PunchHoleResponse{
				Failure: pb.PunchHoleResponse_OFFLINE,
			},
		},
	}
}

// relayRefusedResponse refuses a relay session with reason.
func relayRefusedResponse(reason, relayServer string) *pb.RendezvousMessage {
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				RefuseReason: reason,
				RelayServer:  relayServer,
			},
		},
	}
}

// Refuse reasons of admitSession.
const (
	refuseBillingSuspended    = "Billing suspended"
	refuseBillingBlocked      = "Billing blocked"
	refuseRelayTicketRejected = "Relay authorization rejected"
	refuseRelayUnavailable    = "Relay temporarily unavailable"
)

// ticketIssueTimeout bounds how long admitSession waits for a ticket store
// that is not in this process.
const ticketIssueTimeout = 2 * time.Second

// baseContext is the server's run context, or Background before Start.
func (s *Server) baseContext() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// admitSession decides whether a session from initiatorID to targetID may
// start, on every path that signals one (UDP, TCP and WebSocket, punch and
// relay). Billing refuses a device whose contract does not allow it. With a
// relay uuid the session is also registered with billing, which meters it
// once the relay pairs both sides and records the console account behind
// the request (account, controllerAccount; 0 for none) by its name as the
// session's operator, and the relay ticket is issued, naming the console
// session (consoleSession, a handle; "" for none) whose viewer asked. It
// returns "" when the session may start, otherwise the reason it is
// refused.
func (s *Server) admitSession(tickets relay.Tickets, relayUUID, initiatorID, targetID string, account int64, consoleSession string) string {
	if s.billing != nil {
		if check := s.billing.CheckConnection(targetID); !check.Allowed {
			log.Printf("[signal] Billing denied session to %s: %s", targetID, check.Reason)
			return refuseBillingSuspended
		}
	}
	if relayUUID == "" {
		return ""
	}
	if s.billing != nil {
		if err := s.billing.PrepareRelay(relayUUID, targetID, initiatorID, s.accountName(account)); err != nil {
			log.Printf("[signal] Billing prepare failed for relay to %s: %v", targetID, err)
			return refuseBillingBlocked
		}
	}
	// The account and its console session ride along so the live session
	// names who opened it (saved sign-in binds its use to that browser's
	// own session)
	if tickets == nil {
		tickets = s.ticketStore()
	}
	ctx, cancel := context.WithTimeout(s.baseContext(), ticketIssueTimeout)
	defer cancel()
	err := tickets.Authorize(ctx, relay.Ticket{
		UUID: relayUUID, Initiator: initiatorID, Target: targetID,
		Account: max(account, 0), ConsoleSession: consoleSession,
	})
	switch {
	case err == nil:
		return ""
	case errors.Is(err, relay.ErrTicketsUnavailable):
		log.Printf("[signal] Relay ticket store unavailable (uuid=%q initiator=%q target=%q): %v",
			relayUUID, initiatorID, targetID, err)
		return refuseRelayUnavailable
	default:
		log.Printf("[signal] Rejected relay authorization (uuid=%q initiator=%q target=%q)",
			relayUUID, initiatorID, targetID)
		return refuseRelayTicketRejected
	}
}

// accountName is the user name of the console account with the id, "" for
// none and for an account the server cannot look up.
func (s *Server) accountName(account int64) string {
	if account <= 0 || s.db == nil {
		return ""
	}
	user, err := s.db.GetUserByID(account)
	if err != nil || user == nil {
		return ""
	}
	return user.Username
}

// requireAuthorizedInitiator is authorizeInitiator for a request that does
// not come from the panel's web client.
func (s *Server) requireAuthorizedInitiator(raddr *net.UDPAddr, targetID, token string, udpPort int32) (string, bool) {
	return s.authorizeInitiator(raddr, targetID, token, udpPort, false)
}

// authorizeInitiator enforces that PunchHole/RequestRelay may only be
// started by an authorized initiator, or by the console's
// bridge for the browser's web client: panel is true on its TCP connection,
// which proved itself with the panel proof (see panel_proof.go). The
// sender's address alone never makes a request the panel's.
//
// Authorization sources (first match wins):
//  1. Same Secure TCP session that already completed RegisterPk
//  2. Valid NeoDesk client login token on the punch/relay message
//  3. The panel's web client (panel)
//  4. Live peer with exact ip:port match (FindByAddr)
//  5. PunchHoleRequest.udp_port hint: stock clients advertise their NAT-mapped
//     UDP port; when it uniquely matches a live peer at this public IP, authorize
//     that peer (CGNAT / multi-device same public IP)
//  6. Exactly one live peer at the same public IP (safe FindByIP fallback for
//     stock clients that PunchHole on a new TCP port). Multiple live peers at
//     that IP → initiator_ambiguous_same_nat (no identity inheritance),
//     unless ALLOW_SHARED_NAT_INITIATOR authorizes synthetic shared-nat-initiator
//  7. Anonymous controller-only compatibility identity when
//     ALLOW_LEGACY_OUTBOUND is enabled in open enrollment mode
//
// OPERATOR_ONLY_OUTBOUND additionally requires the session user to have
// device.connect permission; it implies LOGGED_IN_ONLY_INITIATOR semantics.
//
// Managed and locked modes additionally require an approved DB peer row (pending
// enrollment alone is not enough). The panel's web client skips peer-map / DB
// checks: the console checks the account or the guest link at the websocket
// upgrade and each target before it passes a request on. Shared-NAT
// synthetic initiators similarly skip peer-row checks (opt-in connectivity
// tradeoff documented in enrollment docs).
func (s *Server) authorizeInitiator(raddr *net.UDPAddr, targetID, token string, udpPort int32, panel bool) (string, bool) {
	connection := s.cfg.ConnectionSettings()
	if raddr == nil {
		return "", false
	}
	operatorOnly := connection.OperatorOnlyOutbound
	loginOnly := connection.LoggedInOnlyInitiator || operatorOnly

	// The panel's web client is already authenticated at the websocket
	// upgrade. Keep Web Remote working in login-only mode without requiring
	// a stock-client session token.
	if loginOnly && panel {
		return panelWebRemoteInitiatorID, true
	}

	// 1. Same TCP session after RegisterPk (viewer-only / secure TCP).
	if !loginOnly {
		if id := s.tcpSessionPeerID(raddr); id != "" {
			banned := false
			if e := s.peers.Get(id); e != nil {
				banned = e.Banned
			}
			return s.finalizeAuthorizedInitiator(id, raddr, targetID, banned, false)
		}
	}

	// 2. Opaque client login token. In login-only mode, a token must be both
	// syntactically valid and active; no address-based fallback is permitted.
	if tok := strings.TrimSpace(token); tok != "" {
		if !opaqueClientTokenRegexp.MatchString(tok) {
			if loginOnly {
				s.logUnauthorizedInitiator(raddr, "", targetID, "initiator_login_required")
				return "", false
			}
		} else if id, ok := s.authorizeViaClientToken(tok, raddr, targetID, operatorOnly); ok {
			return id, true
		} else if loginOnly {
			// Do not let an expired/revoked token fall through to udp_port or
			// any other identity heuristic when the strict gate is enabled.
			s.logUnauthorizedInitiator(raddr, "", targetID, "initiator_login_required")
			return "", false
		} else {
			// Invalid/expired opaque token: still allow exact udp_port
			// correlation (stronger than IP-only), but never single-IP
			// FindByIP inheritance.
			if match := s.authorizeViaUdpPortHint(raddr, udpPort); match != nil {
				return s.finalizeAuthorizedInitiator(match.ID, raddr, targetID, match.Banned, false)
			}
			return "", false
		}
	}

	if loginOnly {
		s.logUnauthorizedInitiator(raddr, "", targetID, "initiator_login_required")
		return "", false
	}

	// 3. The panel's web client.
	if panel {
		return panelWebRemoteInitiatorID, true
	}

	// 4. Exact registered endpoint (ip:port).
	initiator := s.peers.FindByAddr(raddr)
	if initiator != nil && !initiator.IsExpired(config.RegTimeout) {
		return s.finalizeAuthorizedInitiator(initiator.ID, raddr, targetID, initiator.Banned, false)
	}

	// 5. udp_port hint from PunchHoleRequest (NAT-mapped port of the initiator).
	if match := s.authorizeViaUdpPortHint(raddr, udpPort); match != nil {
		return s.finalizeAuthorizedInitiator(match.ID, raddr, targetID, match.Banned, false)
	}

	// 6. Safe IP-only fallback: stock RustDesk opens PunchHole on a new TCP
	// port after RegisterPk/UDP heartbeat, so FindByAddr misses. Authorize only
	// when exactly one live peer shares this public IP.
	var live []*peer.Entry
	for _, e := range s.peers.FindAllByIP(raddr.IP) {
		if e != nil && !e.IsExpired(config.RegTimeout) {
			live = append(live, e)
		}
	}
	switch len(live) {
	case 0:
		// Official RustDesk permits a controller-only client to send PunchHole
		// or RequestRelay without registering a local device. Keep this
		// compatibility path explicitly opt-in and limited to open enrollment.
		// Never infer another peer identity from a shared public IP; force the
		// synthetic initiator through relay and keep relay ticket checks intact.
		if s.cfg != nil && s.cfg.AllowLegacyOutbound && s.cfg.EnrollmentMode == config.EnrollmentModeOpen {
			id := legacyOutboundInitiatorID(raddr)
			log.Printf("[signal] Accepted legacy controller-only outbound from %s for target %s", raddr.IP, targetID)
			return id, true
		}

		// Never inherit an identity solely from a public IP address. NAT
		// addresses are shared and attacker-controlled source ports are trivial
		// to create.
		s.logUnauthorizedInitiator(raddr, "", targetID, "initiator_not_registered")
		return "", false
	case 1:
		return s.finalizeAuthorizedInitiator(live[0].ID, raddr, targetID, live[0].Banned, false)
	default:
		if connection.AllowSharedNATInitiator {
			log.Printf("[signal] shared-NAT initiator from %s authorized as %s (%d live peers at this IP)",
				raddr.IP, sharedNATInitiatorID, len(live))
			return sharedNATInitiatorID, true
		}
		s.logUnauthorizedInitiator(raddr, "", targetID, "initiator_ambiguous_same_nat")
		return "", false
	}
}

// authorizeViaUdpPortHint resolves the initiator when PunchHole carries the
// client's NAT-mapped UDP port and exactly one live peer at raddr.IP is
// registered on that port. Returns (nil) when the hint is absent
// or ambiguous — never picks an arbitrary same-IP peer.
func (s *Server) authorizeViaUdpPortHint(raddr *net.UDPAddr, udpPort int32) *peer.Entry {
	if raddr == nil || s.peers == nil || udpPort <= 0 || udpPort > 65535 {
		return nil
	}
	hintAddr := &net.UDPAddr{IP: raddr.IP, Port: int(udpPort)}
	if match := s.peers.FindByAddr(hintAddr); match != nil && !match.IsExpired(config.RegTimeout) {
		return match
	}
	// Some clients report the mapped port while the peer map still holds an
	// older NAT mapping on a different port — accept only when exactly one
	// live peer at this IP has UDPAddr.Port == udpPort.
	var matches []*peer.Entry
	for _, e := range s.peers.FindAllByIP(raddr.IP) {
		if e == nil || e.IsExpired(config.RegTimeout) || e.UDPAddr == nil {
			continue
		}
		if e.UDPAddr.Port == int(udpPort) {
			matches = append(matches, e)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return nil
}

// bindTCPSessionPeer records the peer ID on an open tcpPunchConn so a later
// PunchHole on the same Secure TCP session can authorize without UDP heartbeats.
func (s *Server) bindTCPSessionPeer(addrStr, peerID string) {
	if addrStr == "" || peerID == "" {
		return
	}
	key := normalizeAddrKey(addrStr)
	if val, ok := s.tcpPunchConns.Load(key); ok {
		pc := val.(*tcpPunchConn)
		pc.peerID = peerID
	}
}

// tcpSessionPeerID returns the peer ID bound to the TCP punch connection for raddr.
func (s *Server) tcpSessionPeerID(raddr *net.UDPAddr) string {
	if raddr == nil {
		return ""
	}
	return s.peerIDBySessionAddr(raddr.String())
}

// peerIDBySessionAddr returns the peer ID bound to an address-keyed TCP punch
// session, or "" when the address has no bound identity.
func (s *Server) peerIDBySessionAddr(addrStr string) string {
	if addrStr == "" {
		return ""
	}
	key := normalizeAddrKey(addrStr)
	val, ok := s.tcpPunchConns.Load(key)
	if !ok {
		return ""
	}
	pc, ok := val.(*tcpPunchConn)
	if !ok || pc == nil {
		return ""
	}
	return pc.peerID
}

var opaqueClientTokenRegexp = regexp.MustCompile(`(?i)^[a-f0-9]{64}$`)

func hashOpaqueClientToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// authorizeViaClientToken accepts PunchHole/RequestRelay when the stock RustDesk
// client sends a NeoDesk opaque login token (service may be stopped).
func (s *Server) authorizeViaClientToken(token string, raddr *net.UDPAddr, targetID string, operatorOnly bool) (string, bool) {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" || s.db == nil || !opaqueClientTokenRegexp.MatchString(token) {
		return "", false
	}
	sess, err := s.db.GetClientSessionByTokenHash(hashOpaqueClientToken(token))
	if err != nil || sess == nil {
		s.logUnauthorizedInitiator(raddr, "", targetID, "initiator_token_rejected")
		return "", false
	}
	if operatorOnly {
		user, userErr := s.db.GetUserByID(sess.UserID)
		if userErr != nil || user == nil {
			s.logUnauthorizedInitiatorDetails(raddr, sess.ClientID, targetID, "initiator_user_rejected", map[string]string{
				"user_id": strconv.FormatInt(sess.UserID, 10),
			})
			return "", false
		}
		if !auth.RoleHasPermission(user.Role, auth.PermDeviceConnect) {
			s.logUnauthorizedInitiatorDetails(raddr, sess.ClientID, targetID, "initiator_role_denied", map[string]string{
				"username": user.Username,
				"role":     user.Role,
				"user_id":  strconv.FormatInt(user.ID, 10),
			})
			return "", false
		}
	}
	initiatorID := strings.TrimSpace(sess.ClientID)
	if initiatorID == "" {
		// Logged-in but device id unknown — open mode only (no enrollment claim).
		mode := s.cfg.EnrollmentMode
		if mode == "" {
			mode = config.EnrollmentModeOpen
		}
		if mode == config.EnrollmentModeManaged || mode == config.EnrollmentModeLocked {
			s.logUnauthorizedInitiator(raddr, "", targetID, "initiator_session_no_device")
			return "", false
		}
		return fmt.Sprintf("session-user-%d", sess.UserID), true
	}
	// Token initiators must always consult the persisted ban state, including
	// open enrollment mode. Memory entries are cleared on restart and cannot be
	// the authority for a revocation decision.
	banned, err := s.db.IsPeerBanned(initiatorID)
	if err != nil {
		s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_ban_check_failed")
		return "", false
	}
	if banned {
		s.revokeBannedPeerAccess(initiatorID, sess)
		s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_banned")
		return "", false
	}
	// queueManagedClaim=true: account-bound login token may place the device in
	// the managed enrollment queue. IP/address paths must not.
	return s.finalizeAuthorizedInitiator(initiatorID, raddr, targetID, false, true)
}

// finalizeAuthorizedInitiator applies ban / soft-delete / enrollment checks shared
// by live-peer and token-based authorization paths.
//
// queueManagedClaim may only be true for opaque client-login token auth.
// When true and enrollment is managed, an unknown initiator is written to
// pending_device_* so viewer-only mobiles appear in /registrations — connection
// is still denied until operator approval. Locked mode never queues. Address /
// IP-fallback callers must pass false.
func (s *Server) finalizeAuthorizedInitiator(initiatorID string, raddr *net.UDPAddr, targetID string, memoryBanned, queueManagedClaim bool) (string, bool) {
	if memoryBanned {
		s.revokeBannedPeerAccess(initiatorID, nil)
		s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_banned")
		return "", false
	}
	if s.db != nil {
		banned, err := s.db.IsPeerBanned(initiatorID)
		if err != nil {
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_ban_check_failed")
			return "", false
		}
		if banned {
			s.revokeBannedPeerAccess(initiatorID, nil)
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_banned")
			return "", false
		}
		if softDeleted, _ := s.db.IsPeerSoftDeleted(initiatorID); softDeleted {
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_soft_deleted")
			return "", false
		}
		// Defense in depth: still queued for approval must not initiate.
		if pending, _ := s.db.GetConfig("pending_device_" + initiatorID); pending != "" {
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_pending_enrollment")
			return "", false
		}
	}

	mode := s.cfg.EnrollmentMode
	if mode == "" {
		mode = config.EnrollmentModeOpen
	}
	if mode == config.EnrollmentModeManaged || mode == config.EnrollmentModeLocked {
		if s.db == nil {
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_not_enrolled")
			return "", false
		}
		dbPeer, err := s.db.GetPeer(initiatorID)
		if err != nil || dbPeer == nil {
			// Viewer-only clients never RegisterPeer/Pk; queue only from trusted
			// login-token claims so operators can approve them.
			if mode == config.EnrollmentModeManaged && queueManagedClaim && initiatorID != "" {
				clientIP := ""
				if raddr != nil {
					clientIP = raddr.IP.String()
				}
				s.recordPendingEnrollment(initiatorID, clientIP, pendingEnrollmentMeta{})
			}
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_not_enrolled")
			return "", false
		}
		if isInboundOnlyPeer(dbPeer) {
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_inbound_only_device")
			return "", false
		}
	} else if s.db != nil {
		// Open mode still needs to prevent an approved support/OS agent from
		// initiating connections. Do not rely on the in-memory peer map: it
		// does not carry durable device_type metadata.
		dbPeer, err := s.db.GetPeer(initiatorID)
		if err != nil {
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_type_lookup_failed")
			return "", false
		}
		if isInboundOnlyPeer(dbPeer) {
			s.logUnauthorizedInitiator(raddr, initiatorID, targetID, "initiator_inbound_only_device")
			return "", false
		}
	}

	return initiatorID, true
}

func (s *Server) logUnauthorizedInitiator(raddr *net.UDPAddr, initiatorID, targetID, reason string) {
	s.logUnauthorizedInitiatorDetails(raddr, initiatorID, targetID, reason, nil)
}

func (s *Server) logUnauthorizedInitiatorDetails(raddr *net.UDPAddr, initiatorID, targetID, reason string, extra map[string]string) {
	clientHost := ""
	if raddr != nil {
		clientHost = raddr.IP.String()
	}
	details := map[string]string{"reason": reason}
	record, suppressed := s.noteRefusal(audit.ActionConnectionDenied, clientHost, details)
	if !record {
		return
	}
	log.Printf("[signal] Rejected outbound from %s (initiator=%q target=%q reason=%s, %d more since the last)",
		clientHost, initiatorID, targetID, reason, suppressed)
	if s.auditLog == nil {
		return
	}
	for key, value := range extra {
		if value != "" {
			details[key] = value
		}
	}
	if initiatorID != "" {
		details["initiator_id"] = initiatorID
	}
	if targetID != "" {
		details["target_id"] = targetID
	}
	s.auditLog.Log(audit.ActionConnectionDenied, clientHost, targetID, withSuppressed(details, suppressed))
}

// logAuthorizedInitiator records the authorization decision without persisting
// the bearer token. The user is resolved again from the active session so the
// audit entry identifies the account that authorized this specific attempt.
func (s *Server) logAuthorizedInitiator(raddr *net.UDPAddr, initiatorID, targetID, token, transport string) {
	if s.auditLog == nil {
		return
	}
	clientHost := ""
	if raddr != nil {
		clientHost = raddr.IP.String()
	}
	details := map[string]string{
		"reason":       "initiator_authorized",
		"initiator_id": initiatorID,
		"target_id":    targetID,
		"transport":    transport,
	}
	if strings.EqualFold(initiatorID, panelWebRemoteInitiatorID) {
		details["source"] = "panel_web_remote"
	} else if s.db != nil && opaqueClientTokenRegexp.MatchString(strings.TrimSpace(token)) {
		if sess, err := s.db.GetClientSessionByTokenHash(hashOpaqueClientToken(token)); err == nil && sess != nil {
			details["user_id"] = strconv.FormatInt(sess.UserID, 10)
			if user, userErr := s.db.GetUserByID(sess.UserID); userErr == nil && user != nil {
				details["username"] = user.Username
				details["role"] = user.Role
			}
		}
	}
	s.auditLog.Log(audit.ActionConnectionAllowed, clientHost, targetID, details)
}

// recordConnectionSession persists a Metrics-tab session row after the target
// is confirmed online. Debounced in the DB layer for PunchHole retries.
func (s *Server) recordConnectionSession(raddr *net.UDPAddr, initiatorID, targetID, token, transport, relayUUID string) {
	if s.db == nil || strings.TrimSpace(targetID) == "" {
		return
	}
	sess := &db.PeerConnectionSession{
		HostID:    targetID,
		PeerID:    initiatorID,
		Transport: transport,
		RelayUUID: strings.TrimSpace(relayUUID),
		Source:    "signal",
		StartedAt: time.Now().UTC(),
	}
	if raddr != nil {
		sess.PeerIP = raddr.IP.String()
	}
	if strings.EqualFold(initiatorID, panelWebRemoteInitiatorID) {
		sess.PeerName = "Web Remote"
		sess.Username = "web_remote"
	} else if s.db != nil {
		if p, err := s.db.GetPeer(initiatorID); err == nil && p != nil {
			sess.PeerName = strings.TrimSpace(p.Hostname)
			if sess.PeerName == "" {
				sess.PeerName = initiatorID
			}
		}
		if opaqueClientTokenRegexp.MatchString(strings.TrimSpace(token)) {
			if cs, err := s.db.GetClientSessionByTokenHash(hashOpaqueClientToken(token)); err == nil && cs != nil {
				if user, userErr := s.db.GetUserByID(cs.UserID); userErr == nil && user != nil {
					sess.Username = user.Username
				}
			}
		}
	}
	if _, err := s.db.StartPeerConnectionSession(sess); err != nil {
		log.Printf("[signal] connection session record failed: %v", err)
	}
}

func (s *Server) shouldForceRelayForPeers(peerIDs ...string) bool {
	if s.networkPolicy == nil {
		return false
	}
	return s.networkPolicy.ShouldForceRelay(peerIDs...)
}

func (s *Server) applyNetworkRelayPolicy(defaultRelay string, peerIDs ...string) string {
	if s.networkPolicy == nil {
		return defaultRelay
	}
	return s.networkPolicy.ResolveRelay(defaultRelay, peerIDs...)
}

// getRelayServer returns the relay server address to advertise to clients.
// Priority:
//  1. The relay the console's settings name ("Public relay server"), else
//     the configured relay servers (-relay-servers flag / RELAY_SERVERS
//     env): config.GetRelayServers
//  2. Server's detected public IP + relay port (auto-detected via external service)
//  3. LAN IP + relay port (from OS routing table — works for LAN-only setups)
//
// Never returns bare ":port" — that is unusable by remote clients.
func (s *Server) getRelayServer() string {
	relays := s.cfg.GetRelayServers()
	if len(relays) > 0 {
		return relays[0]
	}
	// Use auto-detected public IP if available
	if ip, ok := s.localIP.Load().(string); ok && ip != "" {
		return fmt.Sprintf("%s:%d", ip, s.cfg.RelayPort)
	}
	// Last resort: use LAN IP (better than bare port which is unusable)
	if ip, ok := s.lanIP.Load().(string); ok && ip != "" {
		return fmt.Sprintf("%s:%d", ip, s.cfg.RelayPort)
	}
	// Should not happen — detectLocalIP always detects LAN IP
	log.Printf("[signal] WARN: No relay address available — remote connections will fail")
	return fmt.Sprintf(":%d", s.cfg.RelayPort)
}

// sanitizeClientRelayAddress validates a relay endpoint supplied by a client
// (RequestRelay.RelayServer, PunchHoleSent.RelayServer) before it is echoed
// back to either peer.
//
// RustDesk 1.4.8/1.4.9 clients that are configured with a bare `relay-server`
// (no port) can send the *API* port instead — observed on production as
// `relay=85.14.70.12:21114`. Advertising that back makes both peers dial the
// HTTP API socket, which speaks no relay protocol: the first connection is
// accepted by the API listener and the relay never pairs, so every session
// ends in `[relay] Pair timeout`. Reject those endpoints and fall back to the
// server-configured relay so old and new clients behave the same.
func (s *Server) sanitizeClientRelayAddress(clientRelay string) string {
	configured := s.getRelayServer()
	clientRelay = strings.TrimSpace(clientRelay)
	if clientRelay == "" {
		return configured
	}

	host, portStr, err := net.SplitHostPort(clientRelay)
	if err != nil {
		// Host without a port — keep the host, add the relay port.
		hostOnly := strings.Trim(clientRelay, "[]")
		if hostOnly == "" {
			return configured
		}
		return net.JoinHostPort(hostOnly, strconv.Itoa(s.cfg.RelayPort))
	}

	port, convErr := strconv.Atoi(portStr)
	if convErr != nil || port <= 0 || port > 65535 {
		return configured
	}

	// The configured relay host is authoritative: keep its advertised port even
	// when the client reports a different one for the same host.
	if cfgHost, _, splitErr := net.SplitHostPort(configured); splitErr == nil {
		if strings.EqualFold(strings.Trim(cfgHost, "[]"), strings.Trim(host, "[]")) {
			return configured
		}
	}

	// Ports that belong to other listeners on this host are never a relay.
	switch port {
	case s.cfg.RelayPort:
		return clientRelay
	case s.cfg.APIPort, s.cfg.SignalPort, s.cfg.WSRelayPort():
		log.Printf("[signal] Ignoring client relay endpoint %s (port %d is not the relay); using %s",
			clientRelay, port, net.JoinHostPort(host, strconv.Itoa(s.cfg.RelayPort)))
		return net.JoinHostPort(host, strconv.Itoa(s.cfg.RelayPort))
	}

	return clientRelay
}

// getLANRelayServer returns the relay server address suitable for LAN peers.
// Uses the server's detected LAN IP (from OS routing table) rather than public IP.
// This ensures LAN peers can reach the relay without NAT hairpin support.
func (s *Server) getLANRelayServer(defaultRelay string, peers ...*net.UDPAddr) string {
	if defaultRelay == "" {
		defaultRelay = s.getRelayServer()
	}

	// A peer at the gateway of the server's network comes through that
	// gateway's NAT, so whether it reaches the LAN IP is unknown: on Docker
	// Desktop every client comes from the bridge gateway and none reaches
	// the container's own address. Such a pair gets the named relay only
	// when RELAY_SERVERS or the console's Public relay server names one;
	// otherwise the LAN IP rule below applies as for any peer.
	if gw := s.peerAtGateway(peers...); gw != "" && len(s.cfg.GetRelayServers()) > 0 {
		log.Printf("[signal] peer at the gateway %s; using configured relay=%s, not the LAN IP", gw, defaultRelay)
		return defaultRelay
	}

	// For LAN peers, prefer the server's LAN IP only when it is actually in the
	// peers' private subnet. NAT hairpin (LAN → public IP → LAN) is unreliable
	// on many routers, but Docker bridge IPs are not reachable from LAN
	// clients and must not be advertised as relay addresses.
	if ip, ok := s.lanIP.Load().(string); ok && ip != "" {
		lanIP := net.ParseIP(ip)
		if !isLANRelayReachableFromPeers(lanIP, s.lanNet, peers...) {
			log.Printf("[signal] LAN relay %s is outside peer subnet; using configured/default relay=%s", ip, defaultRelay)
			return defaultRelay
		}

		// Determine relay port: prefer admin-configured port, fall back to default.
		relayPort := s.cfg.RelayPort
		relays := s.cfg.GetRelayServers()
		if len(relays) > 0 {
			if _, portStr, err := net.SplitHostPort(relays[0]); err == nil {
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					relayPort = p
				}
			}
		}
		return fmt.Sprintf("%s:%d", ip, relayPort)
	}
	// LAN IP unknown — fall back to configured/default relay.
	return defaultRelay
}

// peerAtGateway is the gateway of the server's network (lanGateway) when
// one of the peers has its address, else "".
func (s *Server) peerAtGateway(peers ...*net.UDPAddr) string {
	gw, _ := s.lanGateway.Load().(string)
	gwIP := net.ParseIP(gw)
	if gwIP == nil {
		return ""
	}
	for _, p := range peers {
		if p != nil && p.IP.Equal(gwIP) {
			return gw
		}
	}
	return ""
}

func (s *Server) selectPeerRelayServer(defaultRelay string, a, b *net.UDPAddr) (relay string, sameLAN bool, samePublicIP bool) {
	if defaultRelay == "" {
		defaultRelay = s.getRelayServer()
	}
	if a == nil || b == nil {
		return defaultRelay, false, false
	}

	if s.cfg.ConnectionSettings().SameNATRelay && isSamePublicIP(a, b) {
		return s.getRelayServer(), false, true
	}
	if isSameNetwork(a, b, s.lanNet) {
		return s.getLANRelayServer(defaultRelay, a, b), true, false
	}
	return defaultRelay, false, false
}

func isLANRelayReachableFromPeers(lanIP net.IP, lanNet *net.IPNet, peers ...*net.UDPAddr) bool {
	lan4 := lanIP.To4()
	if lan4 == nil || !isPrivateIP(lan4) {
		return false
	}
	for _, peerAddr := range peers {
		if peerAddr == nil {
			continue
		}
		peer4 := peerAddr.IP.To4()
		if peer4 == nil || peer4.IsLoopback() || !isPrivateIP(peer4) {
			continue
		}
		if lan4.Equal(peer4) || sameLANSubnet(lan4, peer4, lanNet) {
			return true
		}
	}
	return false
}

// sameLANSubnet reports whether two IPs share the configured LAN CIDR, or —
// when MASK is unset — the historic IPv4 /24 (first three octets) rule.
func sameLANSubnet(a, b net.IP, lanNet *net.IPNet) bool {
	if lanNet != nil {
		return lanNet.Contains(a) && lanNet.Contains(b)
	}
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	return a4[0] == b4[0] && a4[1] == b4[1] && a4[2] == b4[2]
}

// registerPkResponse is a helper to create a RegisterPkResponse message.
func registerPkResponse(result pb.RegisterPkResponse_Result) *pb.RendezvousMessage {
	return &pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RegisterPkResponse{
			RegisterPkResponse: &pb.RegisterPkResponse{
				Result: result,
			},
		},
	}
}

// isSameNetwork returns true if both addresses are on the same LAN or behind
// the same NAT. Used for LAN detection to enable direct local connections.
//
// Matches the original Rust hbbs logic:
//
//	is_local = (both private IPv4 && same subnet) || (same IP)
//
// Subnet matching uses MASK / -mask when set (CIDR Contains); otherwise the
// historic IPv4 /24 (first three octets) comparison. Loopback (127.x.x.x, ::1)
// connecting to a private IP target is considered "same network" because the
// server is local and both are LAN peers.
func isSameNetwork(a, b *net.UDPAddr, lanNet *net.IPNet) bool {
	if a == nil || b == nil {
		log.Printf("[LAN] isSameNetwork: nil address (a=%v, b=%v)", a, b)
		return false
	}

	// Normalize to IPv4 if possible (handles ::ffff:x.x.x.x mapped addresses)
	aIP := a.IP
	bIP := b.IP
	if a4 := a.IP.To4(); a4 != nil {
		aIP = a4
	}
	if b4 := b.IP.To4(); b4 != nil {
		bIP = b4
	}

	// Same IP — behind the same NAT, or same machine
	if aIP.Equal(bIP) {
		log.Printf("[LAN] isSameNetwork: same IP (%v) → true", aIP)
		return true
	}

	// Loopback detection: if initiator is 127.x or ::1 and target is private IP,
	// treat as same network. This happens when web client or local app connects
	// to localhost server while target is on LAN.
	aLoopback := aIP.IsLoopback()
	bPrivate := isPrivateIP(bIP)
	log.Printf("[LAN] isSameNetwork check: a=%v (loopback=%v), b=%v (private=%v)", aIP, aLoopback, bIP, bPrivate)

	if aLoopback && bPrivate {
		log.Printf("[LAN] isSameNetwork: loopback→private → true")
		return true
	}
	if bIP.IsLoopback() && isPrivateIP(aIP) {
		log.Printf("[LAN] isSameNetwork: private←loopback → true")
		return true
	}

	// Both private IPv4 on the same subnet (MASK CIDR or default /24)
	a4 := aIP.To4()
	b4 := bIP.To4()
	if a4 != nil && b4 != nil && isPrivateIP(a4) && isPrivateIP(b4) {
		if sameLANSubnet(a4, b4, lanNet) {
			if lanNet != nil {
				log.Printf("[LAN] isSameNetwork: same MASK network %s (%v, %v) → true", lanNet, a4, b4)
			} else {
				log.Printf("[LAN] isSameNetwork: same /24 subnet (%v, %v) → true", a4, b4)
			}
			return true
		}
	}

	log.Printf("[LAN] isSameNetwork: no match → false")
	return false
}

// isSamePublicIP returns true when both peers connect from the exact same
// non-private IP address.  This is the classic "behind the same NAT gateway"
// scenario: many consumer/cellular routers refuse hairpin NAT, so direct LAN
// exchange between such peers silently times out.  When this returns true the
// signal handler should force the relay path.
func isSamePublicIP(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	aIP := a.IP
	bIP := b.IP
	if a4 := aIP.To4(); a4 != nil {
		aIP = a4
	}
	if b4 := bIP.To4(); b4 != nil {
		bIP = b4
	}
	if !aIP.Equal(bIP) {
		return false
	}
	// Only treat genuinely public addresses as a hairpin scenario; same-LAN
	// peers (private IPs) keep the existing direct path.
	return !isPrivateIP(aIP) && !aIP.IsLoopback() && !aIP.IsUnspecified()
}

// isPrivateIP returns true if the IP is in a private/local range.
// Handles both 4-byte and 16-byte IP representations.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Normalize to 4-byte IPv4 if possible
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	privateRanges := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		{mustParseCIDR("fc00::/7")},
	}
	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// rejectIfPeerSoftDeleted rejects registration for administrator-removed peers.
// SECURITY (GHSA-3v82-3gf8-fxx8): soft-deleted IDs must not re-enroll via any
// signal path; restoration is explicit via the API/UI only.
func (s *Server) rejectIfPeerSoftDeleted(id, clientHost string) bool {
	if softDeleted, _ := s.db.IsPeerSoftDeleted(id); softDeleted {
		log.Printf("[signal] Rejected registration of deleted peer: %s from %s", id, clientHost)
		s.auditRefusal(audit.ActionPeerRegistrationRejected, clientHost, id, map[string]string{
			"reason": "soft_deleted",
		})
		return true
	}
	return false
}

// checkEnrollmentPermission implements the Dual Key System enrollment policy.
// Returns true if the peer is allowed to register, false otherwise.
//
// Modes:
//   - "open" (default): All devices can register
//   - "managed": New devices need to be pre-approved (exist in DB) or have a token
//   - "locked": Only devices with a valid token binding can register
func (s *Server) checkEnrollmentPermission(peerID, clientIP string) bool {
	mode := s.cfg.EnrollmentMode
	if mode == "" {
		mode = config.EnrollmentModeOpen
	}

	// Open mode — always allow (backward compatible)
	if mode == config.EnrollmentModeOpen {
		s.closePendingEnrollmentInOpenMode(peerID, clientIP)
		return true
	}

	// Check if peer already exists in database (re-registration is always allowed)
	if existingPeer, err := s.db.GetPeer(peerID); err == nil && existingPeer != nil {
		return true
	}

	// Managed mode — allow if there's a pending token with this peer ID pre-bound
	// Admin can pre-bind tokens to specific peer IDs before they register
	if mode == config.EnrollmentModeManaged {
		if token, err := s.db.GetDeviceTokenByPeerID(peerID); err == nil && token != nil {
			if token.Status == db.TokenStatusPending || token.Status == db.TokenStatusActive {
				// Token is valid — activate and bind to peer
				log.Printf("[signal] Enrollment: peer %s matched token %s (managed mode)", peerID, token.Name)
				return true
			}
		}
		// In managed mode, unknown devices are placed into the pending
		// enrollment queue so an operator can review and approve/reject them.
		// The connection is still denied until approval.
		s.recordPendingEnrollment(peerID, clientIP, pendingEnrollmentMeta{})
		s.enrollmentLogf(peerID, "Enrollment: %s from %s waits for approval (managed mode)", peerID, clientIP)
		return false
	}

	// Locked mode — only devices with a valid token binding can register
	if mode == config.EnrollmentModeLocked {
		if token, err := s.db.GetDeviceTokenByPeerID(peerID); err == nil && token != nil {
			if token.Status == db.TokenStatusPending || token.Status == db.TokenStatusActive {
				log.Printf("[signal] Enrollment: peer %s matched token %s (locked mode)", peerID, token.Name)
				return true
			}
		}
		s.enrollmentLogf(peerID, "Enrollment: rejected peer %s from %s (locked mode, no valid token)", peerID, clientIP)
		return false
	}

	return true
}

// closePendingEnrollmentInOpenMode closes the approval request of a device
// that waited in Managed mode and registers now that the mode is Open: the
// request moves to the approved history, so the device is no longer listed
// as waiting and may start sessions (finalizeAuthorizedInitiator refuses
// initiators that still have a request).
func (s *Server) closePendingEnrollmentInOpenMode(peerID, clientIP string) {
	if s.db == nil || peerID == "" {
		return
	}
	key := "pending_device_" + peerID
	raw, err := s.db.GetConfig(key)
	if err != nil || raw == "" {
		return
	}
	if banned, err := s.db.IsPeerBanned(peerID); err != nil || banned {
		return
	}
	// Same fields and key as the API's approval history
	// (enrollmentDecision, enrollment_decision_<id>).
	var decision struct {
		DeviceID   string `json:"device_id"`
		UUID       string `json:"uuid,omitempty"`
		Hostname   string `json:"hostname"`
		Platform   string `json:"platform"`
		Version    string `json:"version"`
		DeviceType string `json:"device_type,omitempty"`
		BundleID   string `json:"bundle_id,omitempty"`
		Tags       string `json:"tags,omitempty"`
		IP         string `json:"ip"`
		Status     string `json:"status"`
		Banned     bool   `json:"banned"`
		DecidedAt  string `json:"decided_at"`
		CreatedAt  string `json:"created_at,omitempty"`
	}
	_ = json.Unmarshal([]byte(raw), &decision)
	decision.DeviceID = peerID
	if decision.IP == "" {
		decision.IP = clientIP
	}
	decision.Status = "approved"
	decision.Banned = false
	decision.DecidedAt = time.Now().UTC().Format(time.RFC3339)
	if data, err := json.Marshal(decision); err == nil {
		if err := s.db.SetConfig("enrollment_decision_"+peerID, string(data)); err != nil {
			log.Printf("[signal] Enrollment: could not save the open mode approval of %s: %v", peerID, err)
		}
	}
	if err := s.db.DeleteConfig(key); err != nil {
		log.Printf("[signal] Enrollment: could not close the request of %s: %v", peerID, err)
		return
	}
	log.Printf("[signal] Enrollment: %s joined in open mode; its approval request is closed", peerID)
	if s.auditLog != nil {
		s.auditLog.Log("device_approved", clientIP, peerID, map[string]string{
			"device_id": peerID, "ip": clientIP, "reason": "joined in open mode",
		})
	}
	if s.eventBus != nil {
		s.eventBus.Publish(events.Event{
			Type: "device_approved",
			Data: map[string]string{"device_id": peerID},
		})
	}
}

// pendingRegisterUUIDField holds, in a waiting request, the uuid of the
// first RegisterPk the device sent for it (hex). The API fills the
// request's name, system and version from system information that carries
// the same uuid (a stock RustDesk client sends nothing else before it is
// approved). Approval does not read it: the key and uuid are still bound by
// the first RegisterPk after approval.
const pendingRegisterUUIDField = "register_uuid"

// notePendingRegisterUUID keeps the uuid of the first RegisterPk of a
// waiting device in its request.
func (s *Server) notePendingRegisterUUID(peerID string, uuid []byte) {
	if s.db == nil || len(uuid) == 0 || len(uuid) > maxRegisterPkUUID {
		return
	}
	key := "pending_device_" + peerID
	raw, err := s.db.GetConfig(key)
	if err != nil || raw == "" {
		return
	}
	request := map[string]any{}
	if json.Unmarshal([]byte(raw), &request) != nil {
		return
	}
	if current, _ := request[pendingRegisterUUIDField].(string); current != "" {
		return
	}
	request[pendingRegisterUUIDField] = fmt.Sprintf("%x", normalizePeerUUIDBytes(uuid))
	data, err := json.Marshal(request)
	if err != nil {
		return
	}
	if err := s.db.SetConfig(key, string(data)); err != nil {
		log.Printf("[signal] Enrollment: could not note the uuid of %s: %v", peerID, err)
	}
}

// pendingEnrollmentInfo mirrors the JSON schema used by the API package
// (pendingDeviceInfo) so that entries created here are readable by the
// enrollment approve/list handlers.
type pendingEnrollmentInfo struct {
	DeviceID  string `json:"device_id"`
	Hostname  string `json:"hostname"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	IP        string `json:"ip"`
	CreatedAt string `json:"created_at"`
}

// pendingEnrollmentMeta carries optional display fields when available.
// Stock RustDesk RegisterPeer/RegisterPk do not include these; a later HTTP
// enrollment or enriching call may supply them.
type pendingEnrollmentMeta struct {
	Hostname string
	Platform string
	Version  string
}

// defaultMaxPendingEnrollments caps the managed-mode approval queue: new
// unknown devices are not queued while it holds this many entries.
const defaultMaxPendingEnrollments = 1000

// recordPendingEnrollment stores an unknown peer in the pending enrollment
// queue (server_config key "pending_device_<id>") so operators can review it.
// Existing created_at is preserved; empty hostname/platform/version may be
// filled when later metadata arrives. Already-rejected devices are never re-queued.
func (s *Server) recordPendingEnrollment(peerID, clientIP string, meta pendingEnrollmentMeta) {
	if s.db == nil {
		return
	}

	// Never re-queue a device that was explicitly rejected.
	if v, err := s.db.GetConfig("rejected_device_" + peerID); err == nil && v != "" {
		return
	}

	key := "pending_device_" + peerID
	if v, err := s.db.GetConfig(key); err == nil && v != "" {
		// Only empty fields are filled; fields this package does not know
		// (those of a NeoDesk client's own request) stay as they are.
		existing := map[string]any{}
		if json.Unmarshal([]byte(v), &existing) != nil {
			return
		}
		changed := false
		for field, value := range map[string]string{
			"hostname": meta.Hostname, "platform": meta.Platform, "version": meta.Version, "ip": clientIP,
		} {
			if current, _ := existing[field].(string); current == "" && value != "" {
				existing[field] = value
				changed = true
			}
		}
		if !changed {
			return
		}
		data, mErr := json.Marshal(existing)
		if mErr != nil {
			log.Printf("[signal] recordPendingEnrollment: marshal enrich failed for %s: %v", peerID, mErr)
			return
		}
		if err := s.db.SetConfig(key, string(data)); err != nil {
			log.Printf("[signal] recordPendingEnrollment: enrich store failed for %s: %v", peerID, err)
		}
		return
	}

	if queued, err := s.db.ListConfigByPrefix("pending_device_"); err != nil || len(queued) >= s.maxPendingEnrollments {
		s.enrollmentLogf(peerID, "recordPendingEnrollment: %s from %s not queued: the approval queue is full (%d entries, err=%v)", peerID, clientIP, len(queued), err)
		return
	}

	info := pendingEnrollmentInfo{
		DeviceID:  peerID,
		Hostname:  meta.Hostname,
		Platform:  meta.Platform,
		Version:   meta.Version,
		IP:        clientIP,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(info)
	if err != nil {
		log.Printf("[signal] recordPendingEnrollment: marshal failed for %s: %v", peerID, err)
		return
	}
	if err := s.db.SetConfig(key, string(data)); err != nil {
		log.Printf("[signal] recordPendingEnrollment: store failed for %s: %v", peerID, err)
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionEnrollmentPending, peerID, clientIP, map[string]string{
			"reason": "queued for approval (managed mode)",
		})
	}
	if s.eventBus != nil {
		s.eventBus.Publish(events.Event{
			Type: events.EventEnrollmentPending,
			Data: map[string]string{
				"device_id": peerID,
				"ip":        clientIP,
			},
		})
	}
}

// keyRefusedConfigPrefix holds, per ID, the address whose RegisterPk the
// server refused for its key (refuseKey): a peer whose key is refused is
// not online, also after a restart or after its entry expired.
const keyRefusedConfigPrefix = "device_key_refused_"

// refuseKey notes that a RegisterPk from addr carried another key than the
// one stored for id. Only a RegisterPk from the peer's own address counts
// (peer.Map.RefuseKey): the peer then takes no session and is not online
// until it registers with the stored key or an administrator approves the
// new one.
func (s *Server) refuseKey(id, addr string) {
	ip := net.ParseIP(hostFromAddrString(addr))
	if s.peers.KeyRefused(id) || !s.peers.RefuseKey(id, ip) {
		return
	}
	log.Printf("[signal] %s is not online while its key is refused", id)
	if err := s.db.SetConfig(keyRefusedConfigPrefix+id, ip.String()); err != nil {
		log.Printf("[signal] Failed to note the refused key of %s: %v", id, err)
	}
}

// acceptKey forgets a refused key of id once a RegisterPk with the stored
// key (or a first one) was accepted.
func (s *Server) acceptKey(id string) {
	if !s.keyRefusedStored(id) {
		return
	}
	if err := s.db.DeleteConfig(keyRefusedConfigPrefix + id); err != nil {
		log.Printf("[signal] Failed to forget the refused key of %s: %v", id, err)
	}
}

// keyRefusedStored reports whether the server noted a refused key for id.
func (s *Server) keyRefusedStored(id string) bool {
	if s.db == nil {
		return false
	}
	v, err := s.db.GetConfig(keyRefusedConfigPrefix + id)
	return err == nil && v != ""
}

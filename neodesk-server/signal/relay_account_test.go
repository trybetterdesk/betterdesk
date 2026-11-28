package signal

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	cryptopkg "github.com/neodeskapp/neodesk/neodesk-server/crypto"
	"github.com/neodeskapp/neodesk/neodesk-server/peer"
	pb "github.com/neodeskapp/neodesk/neodesk-server/proto"
	"github.com/neodeskapp/neodesk/neodesk-server/relay"
)

// TestRelayTicketNamesThePanelAccount: the relay ticket of a session the
// panel's web client opens for a signed-in account names that account,
// and the session is live under it once both sides claimed the ticket. A
// saved sign-in is handed out only to the account whose own session is
// live (L469).
func TestRelayTicketNamesThePanelAccount(t *testing.T) {
	srv, _ := newTestSignalServer(t, config.EnrollmentModeOpen)
	initiatorAddr := udpAddr("127.0.0.1", 51857)
	targetAddr := udpAddr("198.51.100.98", 58012)
	putOnlinePeer(srv, "TGTSIGNIN1", targetAddr.IP.String(), targetAddr.Port, peer.ConnTCP)

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	srv.tcpPunchConns.Store(normalizeAddrKey(initiatorAddr.String()), &tcpPunchConn{conn: server, createdAt: time.Now()})
	srv.panelConns.Store(normalizeAddrKey(initiatorAddr.String()), &panelConn{conn: server, userID: 42})

	const relayUUID = "l469-panel-account-uuid"
	srv.handleRelayResponseForward(&pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				SocketAddr: cryptopkg.EncodeAddr(initiatorAddr),
				Uuid:       relayUUID,
				Union:      &pb.RelayResponse_Id{Id: "TGTSIGNIN1"},
			},
		},
	}, targetAddr)

	if !relay.ClaimRelayPair(relayUUID) || !relay.ClaimRelayPair(relayUUID) {
		t.Fatal("both sides claim the ticket")
	}
	pair, ok := relay.New(nil).Live(relayUUID)
	if !ok || pair.Account != 42 || pair.Target != "TGTSIGNIN1" || pair.Initiator != panelWebRemoteInitiatorID {
		t.Fatalf("live session %+v %v, want account 42 to TGTSIGNIN1 from %s", pair, ok, panelWebRemoteInitiatorID)
	}
}

// TestARelayResponseAfterTheViewerLeftIsForwardedUnderItsTicket: the
// console's web client gets its relay answer from the signal server and
// closes its rendezvous socket, so the panel connection is gone when the
// device's own RelayResponse comes. That response belongs to a session the
// signal server already admitted for the same pair: it is not admitted a
// second time with no account (which the registry refused, logged as a
// rejected authorization, L555), and the ticket keeps its account.
func TestARelayResponseAfterTheViewerLeftIsForwardedUnderItsTicket(t *testing.T) {
	srv, _ := newTestSignalServer(t, config.EnrollmentModeOpen)
	initiatorAddr := udpAddr("127.0.0.1", 51858)
	targetAddr := udpAddr("198.51.100.99", 58013)
	putOnlinePeer(srv, "TGTL555", targetAddr.IP.String(), targetAddr.Port, peer.ConnTCP)

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	got := make(chan int, 16)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			got <- n
		}
	}()
	srv.tcpPunchConns.Store(normalizeAddrKey(initiatorAddr.String()), &tcpPunchConn{conn: server, createdAt: time.Now()})
	srv.panelConns.Store(normalizeAddrKey(initiatorAddr.String()), &panelConn{conn: server, userID: 42})

	const relayUUID = "l555-after-the-viewer-left"
	if refuse := srv.admitSession(nil, relayUUID, panelWebRemoteInitiatorID, "TGTL555", srv.panelAccount(initiatorAddr), srv.panelSession(initiatorAddr)); refuse != "" {
		t.Fatalf("the viewer's own request was refused: %s", refuse)
	}
	// What handleRequestRelayTCP notes for the device's answer
	srv.storePendingUUID("TGTL555", initiatorAddr, relayUUID, panelWebRemoteInitiatorID)
	// The viewer closed its rendezvous socket
	srv.panelConns.Delete(normalizeAddrKey(initiatorAddr.String()))

	srv.handleRelayResponseForward(&pb.RendezvousMessage{
		Union: &pb.RendezvousMessage_RelayResponse{
			RelayResponse: &pb.RelayResponse{
				SocketAddr: cryptopkg.EncodeAddr(initiatorAddr),
				Uuid:       relayUUID,
				Union:      &pb.RelayResponse_Id{Id: "TGTL555"},
			},
		},
	}, targetAddr)
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the device's RelayResponse of an admitted session was not forwarded")
	}
	if !relay.ClaimRelayPair(relayUUID) || !relay.ClaimRelayPair(relayUUID) {
		t.Fatal("both sides claim the ticket")
	}
	if pair, ok := relay.New(nil).Live(relayUUID); !ok || pair.Account != 42 {
		t.Fatalf("live session %+v %v, want account 42", pair, ok)
	}
}

// TestThePunchFallbackTicketNamesTheDesktopAccount: a desktop app signed
// in to NeoDesk punches a hole to a device; the device answers with its
// own RelayResponse (the fallback from a direct connection to the relay).
// The ticket that answer makes names the desktop app's account, as a
// ticket made at RequestRelay does, so the unattended caller check can
// vouch for it (UNATTENDED-CONTRACT.md).
func TestThePunchFallbackTicketNamesTheDesktopAccount(t *testing.T) {
	for _, path := range []struct {
		name  string
		punch func(srv *Server, target, token string, initiator *net.UDPAddr)
	}{
		{"over UDP", func(srv *Server, target, token string, initiator *net.UDPAddr) {
			srv.handlePunchHoleRequest(&pb.PunchHoleRequest{Id: target, Token: token}, initiator)
		}},
		{"over TCP", func(srv *Server, target, token string, initiator *net.UDPAddr) {
			srv.handlePunchHoleRequestTCP(&pb.PunchHoleRequest{Id: target, Token: token}, initiator)
		}},
	} {
		t.Run(path.name, func(t *testing.T) {
			srv, database := newTestSignalServer(t, config.EnrollmentModeOpen)
			srv.cfg.P2PFirst = false
			srv.localIP.Store("198.51.100.20")
			_, targetAddr := attachTestUDPPair(t, srv)
			target := "FALLBK" + strings.ToUpper(strings.ReplaceAll(path.name, "over ", ""))
			putOnlinePeer(srv, target, targetAddr.IP.String(), targetAddr.Port, peer.ConnUDP)
			userID, token := signedInController(t, database, "fallback-"+strings.ReplaceAll(path.name, " ", "-"))
			initiator := udpAddr("203.0.113.72", 51001+len(path.name))

			path.punch(srv, target, token, initiator)
			relayUUID := "punch-fallback-" + uuid.NewString()
			srv.handleRelayResponseForward(&pb.RendezvousMessage{
				Union: &pb.RendezvousMessage_RelayResponse{
					RelayResponse: &pb.RelayResponse{
						SocketAddr: cryptopkg.EncodeAddr(initiator),
						Uuid:       relayUUID,
						Union:      &pb.RelayResponse_Id{Id: target},
					},
				},
			}, targetAddr)
			if !relay.ClaimRelayPair(relayUUID) || !relay.ClaimRelayPair(relayUUID) {
				t.Fatal("both sides claim the ticket")
			}
			pair, ok := relay.New(nil).Live(relayUUID)
			if !ok || pair.Account != userID || pair.Target != target || pair.Initiator == panelWebRemoteInitiatorID || pair.ConsoleSession != "" {
				t.Fatalf("live session %+v %v, want account %d to %s from the desktop app", pair, ok, userID, target)
			}
		})
	}
}

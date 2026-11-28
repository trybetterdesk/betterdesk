package signal

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/crypto"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	pb "github.com/neodeskapp/neodesk/neodesk-server/proto"
)

// TestADrainingPodSendsItsPeersElsewhere: after Drain the signal server
// answers no registration, takes no connection, and has closed the
// WebSocket of a peer registered with it, so the peer's next heartbeat
// goes to another pod. Stop still returns.
func TestADrainingPodSendsItsPeersElsewhere(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SignalPort = 29240
	cfg.RelayPort = 29241
	cfg.EnrollmentMode = config.EnrollmentModeOpen
	dir := t.TempDir()
	cfg.DBPath = dir + "/test.db"
	cfg.KeyFile = dir + "/id_ed25519"
	database, err := db.OpenSQLite(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	database.Migrate()
	defer database.Close()
	kp, err := crypto.LoadOrGenerateKeyPair(cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, kp, database)
	ctx := t.Context()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	register := func() (*pb.RendezvousMessage, error) {
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.SignalPort})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		data, _ := proto.Marshal(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_RegisterPeer{RegisterPeer: &pb.RegisterPeer{Id: "DRAIN0001", Serial: 1}}})
		if _, err := conn.Write(data); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		msg := &pb.RendezvousMessage{}
		return msg, proto.Unmarshal(buf[:n], msg)
	}
	if _, err := register(); err != nil {
		t.Fatalf("before the drain a registration got no answer: %v", err)
	}

	// A peer on the WebSocket signal port
	ws, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://127.0.0.1:%d/", cfg.SignalPort+2), nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer ws.CloseNow()
	data, _ := proto.Marshal(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_RegisterPeer{RegisterPeer: &pb.RegisterPeer{Id: "DRAINWS01", Serial: 1}}})
	if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
		t.Fatal(err)
	}
	readWSProtoSkippingKeepAlive(t, ctx, ws)

	srv.Drain()

	if _, err := register(); err == nil {
		t.Fatal("a draining pod still answers registrations")
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.SignalPort), time.Second); err == nil {
		c.Close()
		t.Fatal("a draining pod still takes TCP signal connections")
	}
	closed := make(chan struct{})
	go func() {
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				close(closed) // the pod closed the peer's socket
				return
			}
		}
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the draining pod kept the peer's WebSocket open")
	}

	stopped := make(chan struct{})
	go func() { srv.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hangs after Drain")
	}
}

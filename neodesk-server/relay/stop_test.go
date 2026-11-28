package relay

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/codec"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	pb "github.com/neodeskapp/neodesk/neodesk-server/proto"
)

// TestStopEndsARunningSession: once the shutdown grace is over the server
// stops, and Stop ends the sessions still running instead of waiting for
// them (a pod would otherwise be killed at the end of its termination
// grace, with its sessions cut the hard way).
func TestStopEndsARunningSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := config.DefaultConfig()
	cfg.RelayPort = port
	srv := New(cfg)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	uuid := "stop-ends-session-uuid"
	authorizeTestRelayPair(t, uuid)
	var legs []net.Conn
	for _, id := range []string{"PEER_B", "PEER_A"} {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := codec.WriteRawProto(c, &pb.RendezvousMessage{Union: &pb.RendezvousMessage_RequestRelay{RequestRelay: &pb.RequestRelay{Uuid: uuid, Id: id}}}); err != nil {
			t.Fatal(err)
		}
		legs = append(legs, c)
	}
	waitRelayPairing(t, srv)

	stopped := make(chan struct{})
	go func() { srv.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop waits for a running session")
	}
	_ = legs[0].SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := legs[0].Read(make([]byte, 1)); err == nil {
		t.Fatal("a leg still reads after Stop")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the leg is still open after Stop")
	}
}

// TestDrainWaitsForForwardedLegs: a leg this pod hands to another pod ends
// with this pod, so Drain gives it the grace like a session of its own.
func TestDrainWaitsForForwardedLegs(t *testing.T) {
	srv := New(config.DefaultConfig())
	srv.ForwardedLegs.Add(1)
	start := time.Now()
	if left := srv.Drain(300 * time.Millisecond); left != 1 {
		t.Fatalf("Drain reports %d running, want the forwarded leg", left)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("Drain did not wait for the forwarded leg")
	}
}

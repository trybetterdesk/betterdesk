package clustertest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/neodeskapp/neodesk/neodesk-server/api"
	"github.com/neodeskapp/neodesk/neodesk-server/audit"
	"github.com/neodeskapp/neodesk/neodesk-server/auth"
	"github.com/neodeskapp/neodesk/neodesk-server/cdap"
	"github.com/neodeskapp/neodesk/neodesk-server/cluster"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/events"
	"github.com/neodeskapp/neodesk/neodesk-server/metrics"
	"github.com/neodeskapp/neodesk/neodesk-server/peer"
	"github.com/neodeskapp/neodesk/neodesk-server/security"
)

// apiPod is the API server and CDAP gateway of one pod, wired to the
// others the way main wires them (clusterRuntime.shareDevices).
type apiPod struct {
	api  *api.Server
	cdap *cdap.Gateway
	port int
}

func (f *fixture) startAPIPod(t *testing.T, name string, routed bool) *apiPod {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.APIPort = freePortTCP(t)
	srv := api.New(cfg, f.database, peer.NewMap(), nil, "test")
	srv.SetBlocklist(security.NewBlocklist())
	auditLog := audit.NewLogger("")
	t.Cleanup(func() { auditLog.Close() })
	srv.SetAuditLogger(auditLog)
	srv.SetEventBus(events.NewBus())
	srv.SetMetrics(metrics.NewCollector())

	gcfg := config.DefaultConfig()
	gcfg.CDAPPort = freePortTCP(t)
	gw := cdap.New(gcfg, f.database, peer.NewMap(), events.NewBus())
	gw.SetJWTManager(auth.NewJWTManager("clustertest-cdap-secret", time.Hour))
	if err := gw.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Stop)
	srv.SetCDAPGateway(gw)

	if routed {
		v := cluster.NewForTest(f.client, f.prefix)
		meshPort := freePortTCP(t)
		mesh, err := cluster.NewMesh(cluster.Config{Name: name, PodIP: "127.0.0.1", Port: meshPort, Secret: f.secret}, v)
		if err != nil {
			t.Fatal(err)
		}
		if err := mesh.Start(meshPort); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(mesh.Stop)
		kv := cluster.NewValkeyKV(v)
		devices := cluster.NewDevices(kv, name)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go devices.Run(ctx)
		gw.SetPresence(devices)
		srv.SetDeviceRouting(cluster.DeviceRouting{Devices: devices, Mesh: mesh, KV: kv})
		mesh.HandleStream(api.ForwardStream, srv.ServeForwarded)
		for callName, h := range srv.DeviceCalls() {
			h := h
			mesh.Handle(callName, func(ctx context.Context, _ string, body []byte) ([]byte, error) { return h(ctx, body) })
		}
	}
	return &apiPod{api: srv, cdap: gw, port: gcfg.CDAPPort}
}

// cdapDevice is a CDAP device's socket.
type cdapDevice struct {
	t    *testing.T
	id   string
	conn *websocket.Conn
}

func connectDevice(t *testing.T, database db.Database, pod *apiPod) *cdapDevice {
	t.Helper()
	id := uniqueID("CD")
	token := "clustertest-device-token-" + id
	if err := database.UpsertPeer(&db.Peer{ID: id, Status: "OFFLINE"}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	if err := database.CreateDeviceToken(&db.DeviceToken{Token: token, TokenHash: hex.EncodeToString(sum[:]), Name: "cdap", PeerID: id, Status: db.TokenStatusActive}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://127.0.0.1:%d/cdap", pod.port), &websocket.DialOptions{Subprotocols: []string{"cdap-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	d := &cdapDevice{t: t, id: id, conn: conn}
	d.send("auth", map[string]string{"method": "device_token", "token": token, "device_id": id})
	d.expect("auth_result")
	d.send("register", map[string]any{"manifest": map[string]any{
		"device":       map[string]string{"name": "Cluster test", "type": "iot"},
		"capabilities": []string{"commands"},
	}})
	d.expect("registered")
	return d
}

func (d *cdapDevice) send(typ string, payload any) {
	d.t.Helper()
	raw, _ := json.Marshal(payload)
	msg, _ := json.Marshal(cdap.Message{Type: typ, Payload: raw})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.conn.Write(ctx, websocket.MessageText, msg); err != nil {
		d.t.Fatalf("send %s: %v", typ, err)
	}
}

func (d *cdapDevice) expect(typ string) map[string]any {
	d.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, raw, err := d.conn.Read(ctx)
		if err != nil {
			d.t.Fatalf("waiting for %s: %v", typ, err)
		}
		var msg cdap.Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			d.t.Fatalf("message %s: %v", raw, err)
		}
		if msg.Type != typ {
			continue
		}
		out := map[string]any{}
		_ = json.Unmarshal(msg.Payload, &out)
		return out
	}
}

// openTerminal opens the device's terminal through pod's API as the
// console does (an in-process caller acting for alice).
func openTerminal(t *testing.T, pod *apiPod, deviceID string) (*websocket.Conn, error) {
	t.Helper()
	h := pod.api.InternalHandler()
	id := api.Identity{Username: "apikey:console-bridge", Role: auth.RoleAdmin, Actor: "alice"}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(api.WithIdentity(r.Context(), id)))
	}))
	t.Cleanup(web.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	browser, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(web.URL, "http")+"/api/cdap/devices/"+deviceID+"/terminal", &websocket.DialOptions{Subprotocols: []string{"cdap-terminal"}})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { browser.CloseNow() })
	return browser, browser.Write(ctx, websocket.MessageText, []byte(`{"cols":80,"rows":24}`))
}

// TestACDAPTerminalOnPodAReachesADeviceOnPodB: the device's socket is on
// pod B; the console opens its terminal through pod A. Pod A finds the
// device in Valkey, passes the request over a signed cluster stream, the
// device gets the terminal with the console's account, and what it
// prints reaches the browser on pod A.
func TestACDAPTerminalOnPodAReachesADeviceOnPodB(t *testing.T) {
	f := newFixture(t, true)
	podA, podB := f.startAPIPod(t, "pod-a", true), f.startAPIPod(t, "pod-b", true)
	device := connectDevice(t, f.database, podB)

	browser, err := openTerminal(t, podA, device.id)
	if err != nil {
		t.Fatalf("terminal through pod A: %v", err)
	}
	start := device.expect("terminal_start")
	if start["operator_name"] != "alice" {
		t.Errorf("operator on the device: %v, want alice", start["operator_name"])
	}
	device.send("terminal_output", map[string]string{"session_id": fmt.Sprint(start["session_id"]), "data": "from pod b", "stream": "stdout"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, raw, err := browser.Read(ctx)
		if err != nil {
			t.Fatalf("no output reached the browser on pod A: %v", err)
		}
		var msg map[string]string
		_ = json.Unmarshal(raw, &msg)
		if msg["type"] == "output" {
			if msg["data"] != "from pod b" {
				t.Fatalf("output %q", msg["data"])
			}
			return
		}
	}
}

// TestWithoutRoutingTheTerminalNeverReachesTheDevice: the same two pods
// without the cluster wiring; the device on pod B never hears of a
// terminal opened through pod A.
func TestWithoutRoutingTheTerminalNeverReachesTheDevice(t *testing.T) {
	f := newFixture(t, true)
	podA, podB := f.startAPIPod(t, "pod-a", false), f.startAPIPod(t, "pod-b", false)
	device := connectDevice(t, f.database, podB)
	_, _ = openTerminal(t, podA, device.id)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for {
		_, raw, err := device.conn.Read(ctx)
		if err != nil {
			return
		}
		if strings.Contains(string(raw), "terminal_start") {
			t.Fatalf("the device got a terminal without routing: %s", raw)
		}
	}
}

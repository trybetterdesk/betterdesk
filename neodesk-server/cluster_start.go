package main

import (
	"context"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/neodeskapp/neodesk/neodesk-server/api"
	"github.com/neodeskapp/neodesk/neodesk-server/cdap"
	"github.com/neodeskapp/neodesk/neodesk-server/cluster"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/events"
	"github.com/neodeskapp/neodesk/neodesk-server/meshcentral"
	"github.com/neodeskapp/neodesk/neodesk-server/relay"
	"github.com/neodeskapp/neodesk/neodesk-server/security"
	sigServer "github.com/neodeskapp/neodesk/neodesk-server/signal"
)

// clusterRuntime is what the server shares with the other instances of its
// installation. Without VALKEY_URL it is the solo runtime: no Valkey, every
// lease held, and the server behaves as before.
type clusterRuntime struct {
	cfg    cluster.Config
	valkey *cluster.Valkey // nil when alone
	leases cluster.Leases
	// draining is set on SIGTERM: the pod reports not ready and takes no
	// new sessions while running ones finish.
	draining atomic.Bool

	// mesh and kv reach the other pods (nil alone); signal and relay are
	// the servers drain hands over.
	mesh   *cluster.Mesh
	kv     cluster.KV
	signal *sigServer.Server
	relay  *relay.Server
	// settings says which settings an instance changed (nil alone).
	settings *events.Bus
}

// valkeyStartWait is how long a start waits for Valkey to answer.
var valkeyStartWait = 30 * time.Second

// dialCluster reads the cluster settings and connects to Valkey when one
// is set. An unreachable Valkey stops the start: an instance that should
// share state but can't would split the installation.
func dialCluster(ctx context.Context, getenv func(string) string) (*clusterRuntime, error) {
	cfg, err := cluster.FromEnv(getenv)
	if err != nil {
		return nil, err
	}
	rt := &clusterRuntime{cfg: cfg, leases: cluster.Solo{}}
	if !cfg.Enabled() {
		return rt, nil
	}
	// Valkey may start after the server (a fresh cluster, a restart of
	// both): wait for it a while before the start stops
	var v *cluster.Valkey
	deadline := time.Now().Add(valkeyStartWait)
	for {
		v, err = cluster.Dial(ctx, cfg)
		if err == nil || time.Now().After(deadline) {
			break
		}
		log.Printf("[cluster] Waiting for Valkey: %v", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	rt.valkey = v
	log.Printf("[cluster] Instance %s shares this installation through Valkey at %s (key prefix %q)",
		cfg.Name, cluster.RedactURL(cfg.ValkeyURL), cfg.KeyPrefix)
	return rt, nil
}

// postgresPool is the PostgreSQL pool of database, nil for SQLite.
func postgresPool(database db.Database) *pgxpool.Pool {
	if pg, ok := database.(*db.PostgresDB); ok {
		return pg.Pool()
	}
	return nil
}

// isSQLiteDSN reports whether dsn names a SQLite file.
func isSQLiteDSN(dsn string) bool {
	lower := strings.ToLower(strings.TrimSpace(dsn))
	return !strings.HasPrefix(lower, "postgres://") && !strings.HasPrefix(lower, "postgresql://")
}

// join records this instance in the database and checks it may run next
// to the others; it returns the number of other live instances. The row is
// written before the check, so two instances that start together both see
// each other and a wrong setup refuses on both.
func (rt *clusterRuntime) join(database db.Database, dsn string, started time.Time) (int, error) {
	store := instanceStore{database}
	self := cluster.Instance{Name: rt.cfg.Name, Clustered: rt.cfg.Enabled(), StartedAt: started, LastSeen: started}
	if err := store.TouchInstance(self); err != nil {
		log.Printf("[cluster] WARN: could not record this instance: %v", err)
	}
	if err := cluster.CheckStart(store, rt.cfg, isSQLiteDSN(dsn), started); err != nil {
		_ = store.RemoveInstance(rt.cfg.Name)
		return 0, err
	}
	others, err := cluster.ListOthers(store, rt.cfg.Name, started)
	if err != nil {
		return 0, err
	}
	return len(others), nil
}

// startLeases picks the lease set: PostgreSQL advisory locks when the
// installation is shared, every lease held when the instance runs alone.
func (rt *clusterRuntime) startLeases(database db.Database) {
	if pool := postgresPool(database); rt.valkey != nil && pool != nil {
		rt.leases = cluster.NewPGLeases(pool, rt.cfg.Name)
	}
}

// startMesh opens the cluster port other pods call.
func (rt *clusterRuntime) startMesh() error {
	mesh, err := cluster.NewMesh(rt.cfg, rt.valkey)
	if err != nil {
		return err
	}
	if err := mesh.Start(rt.cfg.Port); err != nil {
		return err
	}
	rt.mesh = mesh
	rt.kv = cluster.NewValkeyKV(rt.valkey)
	rt.settings = events.NewBus()
	return nil
}

// drain runs on SIGTERM in a cluster, before the servers stop: the pod
// says it is not ready, leaves the pod registry and the peer directory,
// stops taking relay connections and gives running relay sessions the
// shutdown grace (DECISIONS M11). Alone it does nothing.
func (rt *clusterRuntime) drain() {
	if rt == nil || rt.mesh == nil {
		return
	}
	rt.draining.Store(true)
	log.Printf("[cluster] Pod %s drains: no new sessions, %s for running relay sessions", rt.cfg.Name, rt.cfg.ShutdownGrace)
	rt.mesh.Leave()
	if rt.signal != nil {
		rt.signal.PeerMap().Leave()
	}
	if rt.relay != nil {
		left := rt.relay.Drain(rt.cfg.ShutdownGrace)
		log.Printf("[cluster] Pod %s drained (%d relay session(s) still running)", rt.cfg.Name, left)
	}
	rt.mesh.Stop()
}

// ready reports whether the pod should get traffic, and why not.
func (rt *clusterRuntime) ready() (bool, string) {
	if rt == nil {
		return true, ""
	}
	if rt.draining.Load() {
		return false, "shutting down"
	}
	if rt.valkey != nil && !rt.valkey.Healthy() {
		return false, "Valkey does not answer"
	}
	return true, ""
}

func (rt *clusterRuntime) close() {
	if rt == nil {
		return
	}
	rt.leases.Close()
	if rt.valkey != nil {
		_ = rt.valkey.Close()
	}
}

// instanceStore adapts db.Database to cluster.InstanceStore.
type instanceStore struct{ db db.Database }

func (s instanceStore) TouchInstance(inst cluster.Instance) error {
	return s.db.TouchServerInstance(db.ServerInstance(inst))
}

func (s instanceStore) ListInstances(since time.Time) ([]cluster.Instance, error) {
	rows, err := s.db.ListServerInstances(since)
	if err != nil {
		return nil, err
	}
	out := make([]cluster.Instance, len(rows))
	for i, r := range rows {
		out[i] = cluster.Instance(r)
	}
	return out, nil
}

func (s instanceStore) RemoveInstance(name string) error { return s.db.RemoveServerInstance(name) }

// shareDevices records the CDAP devices and MeshCentral agents this pod
// holds and answers the requests and calls other pods pass on for them.
func (rt *clusterRuntime) shareDevices(ctx context.Context, apiSrv *api.Server, cdapGw *cdap.Gateway, meshGw *meshcentral.Gateway) {
	devices := cluster.NewDevices(rt.kv, rt.cfg.Name)
	go devices.Run(ctx)
	if cdapGw != nil {
		cdapGw.SetPresence(devices)
	}
	if meshGw != nil {
		meshGw.SetPresence(devices)
	}
	apiSrv.SetDeviceRouting(cluster.DeviceRouting{Devices: devices, Mesh: rt.mesh, KV: rt.kv})
	rt.mesh.HandleStream(api.ForwardStream, apiSrv.ServeForwarded)
	for name, h := range apiSrv.DeviceCalls() {
		h := h
		rt.mesh.Handle(name, func(ctx context.Context, _ string, body []byte) ([]byte, error) { return h(ctx, body) })
	}
}

// settingsBus is the settings bus, nil when the server runs alone.
func (rt *clusterRuntime) settingsBus() *events.Bus {
	if rt == nil {
		return nil
	}
	return rt.settings
}

// shareSettings joins the settings bus and reads again what another
// instance changed: the configuration (the same reload as SIGHUP), LDAP,
// OIDC and the blocklist. A change here is published for the others.
func (rt *clusterRuntime) shareSettings(ctx context.Context, apiSrv *api.Server, blocklist *security.Blocklist, reload func() error) {
	bus := rt.settings
	bus.Join(ctx, rt.cfg.Name, cluster.NewSettingsLink(rt.valkey))
	apiSrv.SetSettingsBus(bus)
	blocklist.OnChange(func() { events.SettingsChanged(bus, events.SettingsBlocklist, nil) })
	events.OnSettingsChanged(ctx, bus, func(what string, _ map[string]string) {
		var err error
		switch what {
		case events.SettingsConfig:
			err = reload()
		case events.SettingsLDAP:
			apiSrv.InitLDAP()
		case events.SettingsOIDC:
			apiSrv.InitOIDC()
		case events.SettingsBlocklist:
			err = blocklist.Reload()
		default:
			return
		}
		if err != nil {
			log.Printf("[cluster] Reading the %s settings again failed: %v", what, err)
		} else {
			log.Printf("[cluster] Read the %s settings again: another instance changed them", what)
		}
	})
}

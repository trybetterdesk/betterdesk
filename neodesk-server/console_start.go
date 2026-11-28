package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/neodeskapp/neodesk/neodesk-server/api"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/console"
	consoleconfig "github.com/neodeskapp/neodesk/neodesk-server/console/config"
	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/serverinfo"
	"github.com/neodeskapp/neodesk/neodesk-server/console/store"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/events"
	"github.com/neodeskapp/neodesk/neodesk-server/signal"
)

// startConsole starts the web console on its own port: CONSOLE_PORT, else
// 3375, and not at all with CONSOLE_PORT=0. The console works on the
// server's database: PostgreSQL through the server's pool, SQLite through
// its own connections to the same file. The returned function stops the
// console and everything it started. requestRestart ends the process to
// be started again; the console calls it only under a supervisor.
// signalProof returns the panel proof of the signal server in this process
// for an account (signal.Server.PanelProofFor), which the web client's
// bridge presents.
// While the console runs, the signal server takes the client features of
// accounts from it through setFeatures (signal.Server.SetControllerFeatures),
// and answers the clients' HttpProxyRequest with the handler of its client
// API port when it has one (setAPIProxy, signal.Server.SetAPIProxy).
// rt hands the console the installation's leases and whether it runs
// clustered; nil runs it alone.
func startConsole(ctx context.Context, cfg *config.Config, database db.Database, apiSrv *api.Server, bus *events.Bus, signalProof func(userID int64, consoleSession string) []byte, setFeatures func(signal.ControllerFeatures), setAPIProxy func(http.Handler), requestRestart func(), rt *clusterRuntime) (func(), error) {
	// Until the console runs, a computer's chat at the API port answers
	// "starting" (503); a server that ends up without one answers 404
	// (L536)
	running := false
	defer func() {
		if !running {
			apiSrv.NoDeviceChat()
			apiSrv.NoOutsideHandler()
		}
	}()
	ccfg, err := consoleconfig.LoadEnv()
	if err != nil {
		return nil, fmt.Errorf("console configuration: %w", err)
	}
	if ccfg.Port == 0 {
		return func() {}, nil
	}
	linkConsoleToServer(ccfg, cfg, os.Getenv)

	sdb, err := openConsoleStore(cfg, database)
	if err != nil {
		return nil, err
	}
	if err := sdb.Migrate(ctx); err != nil {
		_ = sdb.Close()
		return nil, fmt.Errorf("console schema: %w", err)
	}
	srv, err := console.New(ctx, console.Options{
		Config:      ccfg,
		Store:       sdb,
		API:         apiSrv.InternalHandler(),
		APIListener: apiSrv.ListenerHandler(),
		Events:      bus,
		Roles:       database,
		Version:     Version,
		Commit:      Commit,
		Exit:        requestRestart,
		ServerDB:    cfg.DBPath,
		SignalProof: signalProof,
		PublicRelay: cfg.SetPublicRelayServer,
		Leases:      rt.consoleLeases(),
		Clustered:   rt != nil && rt.cfg.Enabled(),
	})
	if err != nil {
		_ = sdb.Close()
		return nil, err
	}
	if err := srv.Start(ctx); err != nil {
		if errors.Is(err, console.ErrDefaultPortTaken) {
			// An older console may hold the port (DECISIONS A62): signal,
			// relay and API keep running
			srv.Stop()
			_ = sdb.Close()
			log.Printf("ERROR: %v", err)
			log.Printf("ERROR: the server runs without its console. Set CONSOLE_PORT to a free port, or CONSOLE_PORT=0 to turn the console off")
			return func() {}, nil
		}
		_ = sdb.Close()
		return nil, err
	}
	setFeatures(srv.Deps().Access.ClientFeaturesOff)
	if clientAPI := srv.ClientAPI(); clientAPI != nil {
		setAPIProxy(clientAPI.Handler())
		// Outside callers on the API port get what the client API port
		// answers (api/outside.go)
		apiSrv.SetOutsideHandler(clientAPI.Handler())
	}
	// Computers reach their support chat at the API port, where they send
	// everything else (L526): the API hands it to the console
	apiSrv.SetDeviceChat(srv)
	// The end of an unattended session the console vouched for goes to
	// its audit log (A279)
	apiSrv.SetRelayEnded(srv.RelayEnded)
	// The desktop sign-in through the console sends the app to the
	// console's page (DECISIONS A276)
	if mail := srv.Deps().Mail; mail != nil {
		apiSrv.SetConsoleAddress(mail.PanelBaseURLFor)
	}
	running = true
	return func() {
		apiSrv.SetConsoleAddress(nil)
		apiSrv.SetRelayEnded(nil)
		apiSrv.SetDeviceChat(nil)
		apiSrv.SetOutsideHandler(nil)
		setAPIProxy(apiSrv.ListenerHandler())
		setFeatures(nil)
		srv.Stop()
		_ = sdb.Close()
	}, nil
}

// consoleLeases are the leases the console's jobs ask, nil (every job
// runs) without a runtime.
func (rt *clusterRuntime) consoleLeases() kit.Leases {
	if rt == nil || rt.leases == nil {
		return nil
	}
	return rt.leases
}

// applySavedPublicRelay gives the signal server the relay the console's
// settings name ("Public relay server": saved in the console, else
// PUBLIC_RELAY_SERVER), before any device asks for a relay. The console
// tells it again after each save (Options.PublicRelay). A console
// configuration that does not load leaves RELAY_SERVERS.
func applySavedPublicRelay(cfg *config.Config, getenv func(string) string) {
	ccfg, err := consoleconfig.Load(getenv)
	if err != nil {
		return
	}
	info := serverinfo.New(serverinfo.Options{DataDir: ccfg.DataDir, EnvPath: ccfg.EnvPath, Getenv: getenv})
	if relay := info.ReadPublicEndpointEnv().PublicRelayServer; relay != "" {
		cfg.SetPublicRelayServer(relay)
		log.Printf("Relay for devices: %s, the public relay server of the console's settings", relay)
	}
}

// linkConsoleToServer points the console at the API of this process when
// neither NEODESK_API_URL nor HBBS_API_URL names another, and at the
// ports its signal server and relay listen on (the browser viewer's
// sockets, the status page, the attestation) unless WS_HBBS_PORT or
// WS_HBBR_PORT name others.
func linkConsoleToServer(ccfg *consoleconfig.Config, cfg *config.Config, getenv func(string) string) {
	if getenv("NEODESK_API_URL") == "" && getenv("HBBS_API_URL") == "" {
		ccfg.APIHost = net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.APIPort))
	}
	if strings.TrimSpace(getenv("WS_HBBS_PORT")) == "" && cfg.SignalPort > 0 {
		ccfg.SignalPort = cfg.SignalPort
	}
	if strings.TrimSpace(getenv("WS_HBBR_PORT")) == "" && cfg.RelayPort > 0 {
		ccfg.RelayPort = cfg.RelayPort
	}
}

// openConsoleStore opens the console's access to the server's database.
func openConsoleStore(cfg *config.Config, database db.Database) (*store.DB, error) {
	if pg, ok := database.(*db.PostgresDB); ok {
		return store.OpenPostgres(pg.Pool()), nil
	}
	sdb, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("console database: %w", err)
	}
	return sdb, nil
}

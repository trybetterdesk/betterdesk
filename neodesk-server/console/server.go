// Package console serves the web console on its own port: the JSON API, the
// websockets and the built web app (web-ui/build).
//
// Every request passes one pipeline (pipeline.go) whose steps and order
// are those of the Node console's server.js. Route groups add their routes
// to one of two tables: Early, for the client and device API that sit
// before the request language and the CSRF gate, and Router, for
// everything else (routes.go). A websocket upgrade to a path a socket is
// registered for (sockets.go, package console/ws) goes to that socket
// instead.
package console

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/console/access"
	"github.com/neodeskapp/neodesk/neodesk-server/console/admintoken"
	"github.com/neodeskapp/neodesk/neodesk-server/console/alerts"
	"github.com/neodeskapp/neodesk/neodesk-server/console/auditlog"
	"github.com/neodeskapp/neodesk/neodesk-server/console/authimport"
	"github.com/neodeskapp/neodesk/neodesk-server/console/authn"
	"github.com/neodeskapp/neodesk/neodesk-server/console/avatars"
	"github.com/neodeskapp/neodesk/neodesk-server/console/branding"
	"github.com/neodeskapp/neodesk/neodesk-server/console/brandmail"
	"github.com/neodeskapp/neodesk/neodesk-server/console/chatstore"
	"github.com/neodeskapp/neodesk/neodesk-server/console/config"
	"github.com/neodeskapp/neodesk/neodesk-server/console/csrf"
	"github.com/neodeskapp/neodesk/neodesk-server/console/devicegroups"
	"github.com/neodeskapp/neodesk/neodesk-server/console/discovery"
	"github.com/neodeskapp/neodesk/neodesk-server/console/filetransfer"
	"github.com/neodeskapp/neodesk/neodesk-server/console/generator"
	"github.com/neodeskapp/neodesk/neodesk-server/console/goapi"
	"github.com/neodeskapp/neodesk/neodesk-server/console/guestaccess"
	"github.com/neodeskapp/neodesk/neodesk-server/console/helpmail"
	"github.com/neodeskapp/neodesk/neodesk-server/console/housekeeping"
	"github.com/neodeskapp/neodesk/neodesk-server/console/i18n"
	"github.com/neodeskapp/neodesk/neodesk-server/console/impersonation"
	"github.com/neodeskapp/neodesk/neodesk-server/console/jobs"
	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/lifecycle"
	"github.com/neodeskapp/neodesk/neodesk-server/console/limits"
	"github.com/neodeskapp/neodesk/neodesk-server/console/listen"
	"github.com/neodeskapp/neodesk/neodesk-server/console/mail"
	"github.com/neodeskapp/neodesk/neodesk-server/console/ndrelay"
	"github.com/neodeskapp/neodesk/neodesk-server/console/onboard"
	"github.com/neodeskapp/neodesk/neodesk-server/console/passwordlinks"
	"github.com/neodeskapp/neodesk/neodesk-server/console/people"
	"github.com/neodeskapp/neodesk/neodesk-server/console/qr"
	"github.com/neodeskapp/neodesk/neodesk-server/console/remoterelay"
	"github.com/neodeskapp/neodesk/neodesk-server/console/restart"
	"github.com/neodeskapp/neodesk/neodesk-server/console/routes/chat"
	"github.com/neodeskapp/neodesk/neodesk-server/console/routes/settingsbackup"
	"github.com/neodeskapp/neodesk/neodesk-server/console/routes/tickets"
	"github.com/neodeskapp/neodesk/neodesk-server/console/serverinfo"
	"github.com/neodeskapp/neodesk/neodesk-server/console/servermgmt"
	"github.com/neodeskapp/neodesk/neodesk-server/console/session"
	"github.com/neodeskapp/neodesk/neodesk-server/console/statuspush"
	"github.com/neodeskapp/neodesk/neodesk-server/console/store"
	"github.com/neodeskapp/neodesk/neodesk-server/console/updater"
	"github.com/neodeskapp/neodesk/neodesk-server/console/webui"
	"github.com/neodeskapp/neodesk/neodesk-server/console/ws"
	"github.com/neodeskapp/neodesk/neodesk-server/events"
	"github.com/neodeskapp/neodesk/neodesk-server/internal/envvar"
	"github.com/neodeskapp/neodesk/neodesk-server/logging"
)

// Options are what the console needs from the server it runs in.
type Options struct {
	// Config is the console's configuration.
	Config *config.Config
	// Store is the console's database, migrated. The caller closes it
	// after Stop.
	Store *store.DB
	// API is the API server's handler for calls from inside the process
	// (api.Server.InternalHandler).
	API http.Handler
	// APIListener is what the API server's listener serves
	// (api.Server.ListenerHandler). The client API port in proxy mode
	// passes its clients' requests to it, each with the client's address.
	// nil sends them to the API's address over a connection.
	APIListener http.Handler
	// Events is the server's event bus. nil turns the event stream of
	// GoAPI off.
	Events *events.Bus
	// Roles is the server's database with the role overrides. nil leaves
	// every role with its built-in permissions.
	Roles access.OverrideStore
	// Version and Commit are the running binary's (main.Version and
	// main.Commit), for the updater.
	Version, Commit string
	// Exit asks the process to end with the exit status that makes its
	// supervisor start it again (DECISIONS A30). The console calls it only
	// when an installer named a supervisor (NEODESK_SUPERVISOR): after
	// a confirmed restart, an installed update and a restore. Nil never
	// ends the process.
	Exit func()
	// ServerDB is the server's database DSN (its -db flag or DB_URL): the
	// SQLite file a data backup holds and a restore of the server's
	// database is left next to. Empty takes DB_PATH.
	ServerDB string
	// SignalProof returns the frame the web client's bridge writes first on
	// its connection to the signal server of this process, for the bridge
	// of the account with the id, 0 for a guest
	// (signal.Server.PanelProofFor). nil: the bridge sends none, and the
	// signal server treats it as any client.
	SignalProof func(userID int64, consoleSession string) []byte
	// PublicRelay is told the relay the console's settings name after each
	// save of the public endpoints, so the signal server of this process
	// gives devices that relay (config.Config.SetPublicRelayServer). nil
	// tells nobody.
	PublicRelay func(relay string)
	// Leases says which of the once-per-installation jobs this instance
	// runs when several share the database (cluster.Leases; names in
	// kit/leases.go). nil runs them all, as a lone server does.
	Leases kit.Leases
	// Clustered is set when the server shares its installation with other
	// instances (VALKEY_URL): LAN discovery and the mDNS announcement,
	// which would announce one pod, stay off.
	Clustered bool
	// updaterOptions changes the updater's options before it is built:
	// tests give it a GitHub and a binary of their own.
	updaterOptions func(*updater.Options)
}

// Server is the console's HTTP server.
type Server struct {
	cfg      *config.Config
	deps     *kit.Deps
	early    *kit.Router
	router   *kit.Router
	pipeline http.Handler
	jobs     *jobs.Registry
	// net are the listeners (listeners.go)
	net listeners
	// authImport says where the old console's auth.db is (Start imports
	// it).
	authImport authimport.Options
	// apiListener is Options.APIListener, for the client API port
	apiListener http.Handler
	// tokens are the API tokens (package admintoken); tokenRefusals keeps
	// the audit log of refused tokens to one entry a minute per token
	tokens        *admintoken.Service
	tokenRefusals *onceAMinute
	// impersonation holds "Sign in as" to read-only (package
	// impersonation): a step of the pipeline and the socket upgrades
	impersonation *impersonation.Service
	// proxyHint logs once that a proxy TRUST_PROXY ignores is in front
	proxyHint untrustedProxyHint
}

// clientAPIPort is the client API port while the console listens on it
// (API_PORT while API_ENABLED is on), 0 otherwise.
func clientAPIPort(cfg *config.Config) int {
	if !cfg.APIEnabled {
		return 0
	}
	return cfg.APIPort
}

// New builds the console server: its services, the pipeline and the
// routes of every group. Nothing runs before Start.
func New(ctx context.Context, opts Options) (*Server, error) {
	cfg := opts.Config
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	s := &Server{cfg: cfg, early: kit.NewRouter(), router: kit.NewRouter(), jobs: jobs.New(), apiListener: opts.APIListener}
	// lease is the Held check of one job, for the services that take one
	lease := func(name string) func() bool {
		return func() bool { return opts.Leases == nil || opts.Leases.Held(name) }
	}
	// The start steps below create tables and rows once (the chat's and
	// the tokens' tables, the old chat history, the sessions' columns):
	// instances that start together take turns
	unlock, err := opts.Store.LockInstallation(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := os.MkdirAll(cfg.UploadsDir, 0o755); err != nil {
		logging.Logf("console", "WARN: cannot create the uploads folder %s: %v", cfg.UploadsDir, err)
	}
	if err := s.loadCertificates(); err != nil {
		return nil, err
	}
	// A session secret file that holds no usable secret does not stop the
	// console: it starts with the last good secret or a new one, and the
	// notice goes into the log and the console's activity log (L399)
	secret, secretNotice, err := session.LoadSecretNotice(getenv, cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("session secret: %w", err)
	}

	// The console serves HTTPS only when its certificate loaded. HTTPS mode
	// without one runs on plain HTTP: the cookies keep their HTTPS names
	// without Secure, and pages do not ask the browser to upgrade.
	secure := cfg.HTTPS && s.net.cert != nil

	audit := auditlog.New(opts.Store)
	if secretNotice != "" {
		if err := audit.Write(ctx, 0, "session_secret_replaced", secretNotice, ""); err != nil {
			logging.Logf("console", "WARN: %v", err)
		}
	}
	if cfg.WebUIDir == "" && !webui.HasEmbeddedBuild() {
		logging.Logf("console", "WARN: this binary was built without the web app (go run ./cmd/embed-webui before go build) and WEB_UI_DIR is not set: the console answers no pages")
	}
	host := webui.New(webui.Options{
		Embedded:   cfg.WebUIDir == "",
		Dir:        cfg.WebUIDir,
		HTTPS:      secure,
		Production: cfg.Production,
		Session: func(r *http.Request) (bool, string) {
			user := kit.User(r)
			if user == nil {
				return false, ""
			}
			return true, user.Role
		},
		Secure:   func(r *http.Request) bool { return cfg.TrustProxy.Scheme(r) == "https" },
		ClientIP: cfg.TrustProxy.ClientIP,
	})
	sessions, err := session.New(ctx, session.Options{
		DB:         opts.Store,
		Secret:     secret,
		HTTPS:      cfg.HTTPS,
		Secure:     secure,
		Policy:     session.PolicyFromEnv(getenv),
		TrustProxy: cfg.TrustProxy,
		Audit: func(ctx context.Context, userID int64, action, details, ip string) {
			if err := audit.Write(ctx, userID, action, details, ip); err != nil {
				logging.Logf("console", "WARN: %v", err)
			}
		},
		OnError: func(w http.ResponseWriter, r *http.Request, err error) {
			host.ServerError(w, r, err, http.StatusInternalServerError)
		},
		CleanupLease: lease(kit.LeasePanelSessionCleanup),
	})
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	protector, err := csrf.New(csrf.Options{
		Secret:        secret,
		HTTPS:         cfg.HTTPS,
		Secure:        secure,
		SecureRequest: sessions.SecureCookie,
		CookieAuth:    s.cookieAuth,
		BodyToken:     csrfBodyToken,
		OnError:       host.CSRFError,
	})
	if err != nil {
		return nil, fmt.Errorf("csrf: %w", err)
	}

	bundle := i18n.New(cfg.LangDir, cfg.DefaultLanguage)
	if cfg.LangDir == "" && cfg.Static != nil {
		// The language files in the binary, read only
		if bundle.FS, err = fs.Sub(cfg.Static, "lang"); err != nil {
			return nil, fmt.Errorf("the language files in the binary: %w", err)
		}
		bundle.Dir = filepath.Join("(built in)", "lang")
	}
	bundle.Logf = func(format string, args ...any) { logging.Logf("console", format, args...) }
	bundle.Load()
	languages := &i18n.Handlers{
		Bundle:       bundle,
		Production:   cfg.Production,
		SecureCookie: sessions.SecureCookie,
		PreferredLanguage: func(r *http.Request) string {
			if user := kit.User(r); user != nil {
				return user.PreferredLanguage
			}
			return ""
		},
		Logf: func(format string, args ...any) { logging.Logf("console", "ERROR: "+format, args...) },
	}

	api := goapi.New(opts.API, goapi.WithHost(cfg.APIHost), goapi.WithEventBus(opts.Events), goapi.WithActor(accountName), goapi.WithToken(tokenName))

	s.deps = &kit.Deps{
		Router:   s.router,
		Early:    s.early,
		Config:   cfg,
		Store:    opts.Store,
		Sessions: sessions,
		CSRF:     protector,
		Access:   access.New(opts.Store, access.NewDBRoleSource(opts.Roles), access.Options{DeviceScopeDefault: cfg.DeviceScopeDefault}),
		Limits: limits.NewSet(limits.Options{
			ClientIP: cfg.TrustProxy.ClientIP,
			UserKey:  userKey,
			Getenv:   getenv,
		}),
		I18n:  languages,
		WebUI: host,
		GoAPI: api,
		Audit: audit,
		// The unattended sessions the server vouched for, until the relay
		// ends them (RelayEnded)
		Unattended: onboard.NewUnattendedBook(nil),
		Log:        kit.NewLogger(cfg.LogLevel, cfg.Production),
		Jobs:       s.jobs,

		Leases:    opts.Leases,
		Clustered: opts.Clustered,
	}
	s.deps.ServerInfo = serverinfo.New(serverinfo.Options{
		PubKeyPath: cfg.PubKeyPath,
		APIKeyPath: cfg.APIKeyPath,
		DBPath:     cfg.DBPath,
		APIURL:     cfg.APIURL,
		GoAPIPort:  cfg.GoAPIPort,
		APIPort:    cfg.APIPort,
		// clients are given the client API port while it is on (A166)
		ClientAPIPort:  clientAPIPort(cfg),
		ClientAPIHTTPS: cfg.APIEnabled && s.net.apiCert != nil,
		DataDir:        cfg.DataDir,
		EnvPath:        cfg.EnvPath,
		OnPublicRelay:  opts.PublicRelay,
		IsDocker:       cfg.Docker,
		Getenv:         getenv,
		ComposePath:    cfg.ComposePath,
		GoAPI:          api,
		QR: func(text string) (string, error) {
			return qr.PNGDataURL(text, qr.Options{Width: 256, Margin: 2})
		},
		Logger: s.deps.Log,
	})
	s.deps.Avatars = avatars.New(avatars.Options{DB: opts.Store, Logger: s.deps.Log.Child("Avatar")})
	// The fonts an install of the Node console has go to the new folder
	// once, before the branding lists them
	if err := copyOldFonts(cfg.OldFontsDir, cfg.FontsDir); err != nil {
		logging.Logf("console", "WARN: installed fonts: %v", err)
	}
	// The branding's cache is the one copy of the settings: every write
	// goes through this service. Font downloads go through its outbound
	// guard.
	s.deps.Branding, err = branding.New(branding.Options{
		DB: opts.Store, UploadsDir: cfg.UploadsDir, FontsDir: cfg.FontsDir, FontCacheFile: cfg.FontCacheFile,
		TempDir: cfg.TempDir, ThemesDir: cfg.ThemesDir, PalettesFile: cfg.PalettesFile, FaviconFile: cfg.FaviconFile,
		Files: cfg.Static,
	})
	if err != nil {
		return nil, fmt.Errorf("branding: %w", err)
	}
	s.deps.GuestAccess = guestaccess.New(guestaccess.Options{HTTPS: cfg.HTTPS, Secure: secure, GoAPI: api})
	s.deps.FileTransfer = filetransfer.New(filetransfer.Options{Dir: cfg.TransfersDir, Logger: s.deps.Log})
	s.jobs.Add("file transfer cleanup", s.deps.FileTransfer.Run)
	// Under a supervisor a restart is the process's own exit (A30);
	// otherwise the restart runs through the service manager as it did,
	// and nothing ends the process.
	restartServer := s.deps.ServerInfo.RestartServer
	var exit func()
	if supervisor := updater.Supervisor(getenv); supervisor != "" && opts.Exit != nil {
		restartServer, exit = restart.SupervisorRestart(supervisor), opts.Exit
	}
	s.deps.Restart = restart.New(restart.Options{
		DataDir:       cfg.DataDir,
		GoAPI:         api,
		RestartServer: restartServer,
		Rollbacks:     map[string]restart.Rollback{"connection-mode": restart.ConnectionModeRollback(s.deps.ServerInfo)},
		Exit:          exit,
		Logger:        s.deps.Log,
	})
	s.deps.Generator = generator.New(generator.Options{
		DB: opts.Store, ServerInfo: s.deps.ServerInfo, DataDir: cfg.DataDir, ConsoleDir: cfg.ConsoleDir,
		ArtifactDir: cfg.AgentArtifactDir, Embedded: cfg.GeneratorEmbedded, WorkerEnabled: cfg.AgentBuildWorker,
		PollInterval: cfg.AgentBuildPoll, Cooldown: cfg.AgentBuildCooldown, Logger: s.deps.Log,
	})
	s.deps.DeviceGroups = devicegroups.New(devicegroups.Options{DB: opts.Store, Access: s.deps.Access})
	s.deps.Backend = goapi.NewBackend(api, devicegroups.DeviceStore{Groups: s.deps.DeviceGroups})
	s.deps.SetupGuide = s.newSetupGuide(opts.Store, api)
	// One backup service for the backup routes and the data backup the
	// updater keeps before an install
	backups := settingsbackup.NewBackups(s.deps, opts.ServerDB)
	updates := updater.Options{
		DataDir:    cfg.DataDir,
		ConsoleDir: cfg.ConsoleDir,
		EnvFile:    getenv("NEODESK_ENV_FILE"),
		Version:    opts.Version,
		Commit:     opts.Commit,
		Docker:     cfg.Docker,
		Getenv:     getenv,
		DataBackup: backups,
		Setting:    readSetting(opts.Store),
		Logger:     s.deps.Log.Child("UPDATE"),
	}
	if opts.updaterOptions != nil {
		opts.updaterOptions(&updates)
	}
	s.deps.Updater = updater.New(updates)
	s.deps.Mail = mail.New(mail.Options{
		DB:          opts.Store,
		Transport:   &mail.SMTP{},
		Getenv:      getenv,
		TLSVerify:   cfg.SMTPTLSVerify,
		RequireTLS:  cfg.SMTPRequireTLS,
		Port:        cfg.Port,
		HTTPSPort:   cfg.HTTPSPort,
		PanelHost:   s.deps.ServerInfo.ReadPanelPublicHostValue,
		ServesHTTPS: func() bool { return s.net.cert != nil },
		Logger:      s.deps.Log.Child("Email"),
		// The alert and help request mails: the default language and the branding
		Texts: func() *i18n.Bundle {
			if s.deps.I18n == nil {
				return nil
			}
			return s.deps.I18n.Bundle
		},
		Branding: func() brandmail.Branding { return brandmail.Of(s.deps.Branding) },
	})
	// Alert mails and evaluations beside a request end with the console:
	// the job below cancels them and waits for them when the jobs stop.
	alertWork, stopAlertWork := context.WithCancel(context.Background())
	s.deps.Alerts = alerts.New(alerts.Options{
		DB:   opts.Store,
		Mail: s.deps.Mail,
		Devices: func(ctx context.Context) ([]*goapi.Object, error) {
			return append(api.GetAllPeers(ctx, false), api.GetAllRemoteTargets(ctx, "", false)...), nil
		},
		Logger:  s.deps.Log.Child("AlertEngine"),
		Context: alertWork,
		Lease:   lease(kit.LeaseAlertSweep),
	})
	s.jobs.Add("alert engine", func(ctx context.Context) {
		<-ctx.Done()
		stopAlertWork()
		s.deps.Alerts.Wait()
	})
	s.jobs.Add("alert sweep", s.deps.Alerts.Run)
	// Messages the API server stores for agents reach the chat's sockets
	s.jobs.Add("chat events", func(ctx context.Context) { chat.HubOf(s.deps).WatchEvents(ctx, api.Events) })
	// A computer whose credential ends loses its chat socket (L539)
	s.jobs.Add("chat device credentials", func(ctx context.Context) { chat.HubOf(s.deps).WatchDeviceCredentials(ctx, api.Events) })
	s.jobs.Add("chat device recheck", func(ctx context.Context) { chat.HubOf(s.deps).RunDeviceRecheck(ctx) })
	s.jobs.Add("chat wait mail", func(ctx context.Context) { chat.RunWaitMail(ctx, s.deps) })
	s.jobs.Add("help request mail", helpmail.New(helpmail.Options{
		DB: opts.Store, Mail: s.deps.Mail, Events: api.Events, Logger: s.deps.Log.Child("HelpRequestEmail"),
		Lease: lease(kit.LeaseHelpRequestMail),
	}).Run)
	badParam := func(w http.ResponseWriter, r *http.Request, err error) {
		host.ServerError(w, r, err, http.StatusBadRequest)
	}
	s.early.OnBadParam(badParam)
	s.router.OnBadParam(badParam)

	s.deps.Authn, err = authn.New(authn.Options{
		DB:       opts.Store,
		GoAPI:    api,
		Settings: authn.SettingsFromEnv(getenv, cfg.DataDir, cfg.KeysPath),
		QR: func(text string) (string, error) {
			return qr.PNGDataURL(text, qr.Options{Width: 256, Margin: 2})
		},
		Log: s.deps.Log.Child("AUTH"),
	})
	if err != nil {
		return nil, fmt.Errorf("sign-in service: %w", err)
	}
	// The console's own revoke of a device's tokens reaches the chat as
	// the API's does, through the event bus (L539)
	s.deps.Authn.OnDeviceTokensRevoked(func(deviceID string) {
		if opts.Events != nil {
			opts.Events.Publish(events.Event{Type: events.EventDeviceCredentialsEnded, Data: map[string]string{"id": deviceID}})
		}
	})

	// The chat's tables beside the messages the API server keeps (A242)
	if err := chatstore.Ensure(ctx, opts.Store); err != nil {
		return nil, fmt.Errorf("chat: %w", err)
	}
	s.deps.Chat = chatstore.New(opts.Store, nil)
	// What the tickets of the receiver app add to the tickets tables (A277)
	if err := tickets.Ensure(ctx, opts.Store); err != nil {
		return nil, err
	}
	// The links that let a person choose a password (invites, resets)
	if err := passwordlinks.Ensure(ctx, opts.Store); err != nil {
		return nil, err
	}
	// What an admin requires of one account's sign-in, and the browsers
	// accounts signed in from
	if err := authn.EnsureAccountTables(ctx, opts.Store); err != nil {
		return nil, err
	}
	// End dates, inactivity exceptions and email address changes
	if err := lifecycle.Ensure(ctx, opts.Store); err != nil {
		return nil, err
	}
	// The time zones of the people (the user's page, Your account)
	if err := people.Ensure(ctx, opts.Store); err != nil {
		return nil, err
	}
	// Once: the history of the chat of version 1 into its conversations
	if r, err := s.deps.Chat.ImportLegacy(ctx); err != nil {
		return nil, fmt.Errorf("chat: import the history of version 1: %w", err)
	} else if r != (chatstore.LegacyReport{}) {
		logging.Logf("console", "[Chat] moved the history of version 1: %d direct, %d in groups, %d to their computers, %d to old messages", r.Direct, r.Groups, r.Devices, r.Old)
	}

	s.tokens, err = admintoken.New(ctx, admintoken.Options{DB: opts.Store, Lease: lease(kit.LeaseAPITokenEnds)})
	if err != nil {
		return nil, fmt.Errorf("API tokens: %w", err)
	}
	s.tokenRefusals = newOnceAMinute()
	s.deps.AdminTokens = s.tokens
	// What a token made ends with it (admintoken/ends.go): the sessions
	// that run on its guest links end with the links, and the sweep ends
	// what expired and deleted tokens made, with an audit entry each
	s.tokens.OnEnd(func(_ context.Context, e *admintoken.Ending) {
		for _, id := range e.GuestLinks {
			s.deps.GuestAccess.Revoke(id)
		}
	})
	s.jobs.Add("API token ends", func(ctx context.Context) {
		s.tokens.Run(ctx, func(e *admintoken.Ending, err error) {
			if err != nil {
				logging.Logf("console", "WARN: ending what ended API tokens made: %v", err)
				return
			}
			var user int64
			if e.Token != nil {
				user = e.Token.UserID
			}
			if err := s.deps.Audit.Write(context.WithoutCancel(ctx), user, e.AuditAction(), e.AuditText(), ""); err != nil {
				logging.Logf("console", "WARN: audit of an API token's end: %v", err)
			}
		})
	})

	s.jobs.Add("session cleanup", sessions.RunCleanup)
	s.deps.Sockets = ws.New(ws.Options{
		Session:       ws.SessionOf(sessions),
		Permission:    ws.PermissionOf(s.deps.Access),
		SectionAccess: ws.SectionAccessOf(s.deps.Access),
		Origins: ws.OriginPolicy{
			Allowed:      ws.ParseAllowedOrigins(getenv("WS_ALLOWED_ORIGINS")),
			AllowMissing: envvar.SwitchOr(getenv("ND_ALLOW_MISSING_ORIGIN"), false),
		},
		ClientIP:  cfg.TrustProxy.ClientIP,
		SessionID: sessions.CookieSessionID,
	})
	// A session that ends takes its sockets along (A239)
	sessions.OnEnd(s.deps.Sockets.EndSessions)
	s.deps.StatusPush = statuspush.New(statuspush.Options{Events: api.Events, Cascade: s.deps.DeviceGroups.CascadePeerIDChange})
	s.jobs.Add("device status push", s.deps.StatusPush.Run)
	s.deps.Relay = ndrelay.New(ndrelay.Options{VerifyDevice: s.deps.Authn.VerifyDeviceWSAuth})
	s.jobs.Add("nd-relay session cleanup", s.deps.Relay.Run)
	s.deps.RemoteRelay = remoterelay.New(remoterelay.Options{
		VerifyDevice: s.deps.Authn.VerifyDeviceWSAuth,
		DB:           opts.Store,
		CanAccess:    s.deps.DeviceGroups.UserCanAccessDevice,
		FeaturesOff:  s.deps.Access.ClientFeaturesOff,
	})
	// Server management. Relative paths and the console's folder are
	// CONSOLE_DIR, the old console's working directory. A
	// restart of this process's own service is its exit under a supervisor
	// (A30, spec updater-installers 4.6).
	s.deps.ServerMgmt = servermgmt.New(servermgmt.Options{
		Getenv: getenv, WorkDir: cfg.ConsoleDir,
		RestartSelf: func() bool {
			return s.deps.Restart.ExitLater(2*time.Second, "[SERVER-MGMT] Restarting after a restart of the server from server management...")
		},
	})
	// The rest of the old console's start sequence: the hourly clean-up,
	// the stale device sweep, LAN discovery and the mDNS announcement.
	s.authImport = authimport.FromEnv(getenv, cfg.DataDir)
	sweeps := housekeeping.New(housekeeping.Options{DB: opts.Store, StalePeers: s.deps.DeviceGroups.CleanupStaleOnlinePeers,
		StatusSyncInterval: getenv("STATUS_SYNC_INTERVAL"), HeartbeatStaleThreshold: getenv("HEARTBEAT_STALE_THRESHOLD"),
		IntegrationLease: lease(kit.LeaseRetention), StatusSyncLease: lease(kit.LeaseStalePeerSync)})
	s.jobs.Add("integration housekeeping", sweeps.RunIntegration)
	s.jobs.Add("online status sync", sweeps.RunStatusSync)
	// The jobs start after the listeners and announce the port and scheme
	// of the one that serves the console (listeners.go). A clustered
	// server announces nothing: a pod's own address is not where people
	// reach the installation.
	lan := discovery.FromEnv(getenv, discovery.Settings{PubKeyPath: cfg.PubKeyPath, APIPort: float64(cfg.APIPort), Version: cfg.Version})
	if !opts.Clustered {
		s.jobs.Add("LAN discovery", func(ctx context.Context) { discovery.NewLAN(s.announced(lan)).Run(ctx) })
	}
	// The old console announced itself over mDNS only where someone had
	// installed bonjour-service by hand; no installer or image did. So the
	// announcement runs only when PANEL_MDNS asks for it.
	if mdns := getenv("PANEL_MDNS"); mdns != "" && envvar.SwitchOr(mdns, true) && !opts.Clustered {
		s.jobs.Add("mDNS announcement", func(ctx context.Context) { discovery.NewMDNS(s.announced(lan)).Run(ctx) })
	}
	registerRoutes(s.deps, backups)
	registerSockets(s.deps, opts.SignalProof)
	s.newClientAPI()
	s.impersonation = impersonation.New(s.deps)
	s.pipeline = s.buildPipeline()
	return s, nil
}

// accountName is the name of the account signed in on the request ctx
// belongs to, "" for none: the person the API server records as the
// creator or handler of what a call makes (goapi.WithActor).
func accountName(ctx context.Context) string {
	if s := session.FromContext(ctx); s != nil {
		if user := s.User(); user != nil {
			return user.Username
		}
	}
	return ""
}

// tokenName is the public id of the API token the request ctx belongs to
// came with, "" for a request without one: the API server records it on
// the credentials a call makes, so that they end with the token
// (goapi.WithToken).
func tokenName(ctx context.Context) string {
	if use := admintoken.FromContext(ctx); use != nil && use.Token != nil {
		return use.Token.ID
	}
	return ""
}

// userKey is the id of the signed-in account as the rate limiters key it.
func userKey(r *http.Request) string {
	if id := kit.UserID(r); id != 0 {
		return fmt.Sprint(id)
	}
	return ""
}

// Router is the table of the console's routes (step 18 of the pipeline).
func (s *Server) Router() *kit.Router { return s.router }

// Early is the table of the client and device API routes, which sit
// before the request language and the CSRF gate (steps 12 and 13).
func (s *Server) Early() *kit.Router { return s.early }

// RelayEnded is the relay's end of the relay session uuid: an unattended
// session the console vouched for gets its end in the audit log, with how
// long it ran.
func (s *Server) RelayEnded(uuid string) { s.deps.Unattended.End(uuid) }

// Deps is what the route groups were registered with.
func (s *Server) Deps() *kit.Deps { return s.deps }

// Jobs is the registry of the console's background work.
func (s *Server) Jobs() *jobs.Registry { return s.jobs }

// ServeHTTP sends a request through the pipeline. An upgrade to a socket
// the console has (console/ws) goes to that socket, outside the pipeline
// (but for an impersonation, which opens only some, RefuseUpgrade),
// as Node's upgrade listener ran outside Express; any other upgrade
// passes the pipeline like a plain request. The routing report
// (routing.go), when switched on, answers before all of them, and a
// request under ClientAPIPath goes to the client API (clientapipath.go).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DebugRouting && r.Method == http.MethodGet && r.URL.Path == routingPath {
		routingReport(w, r)
		return
	}
	if s.serveClientAPIPath(w, r) {
		return
	}
	if s.deps.Sockets.Serves(r) {
		// A browser that views the console as another account opens only
		// the sockets that push what the account may see
		if s.impersonation.RefuseUpgrade(w, r, s.deps.Sockets.PatternOf(r)) {
			return
		}
		s.deps.Sockets.ServeHTTP(w, r)
		return
	}
	s.pipeline.ServeHTTP(w, r)
}

// Start opens the listeners (listeners.go), starts the background jobs and
// serves until ctx ends or Stop is called.
//
// Before it listens it imports the old console's auth.db when there is
// one that was never imported (package authimport), loads the branding
// settings into their cache and looks after the first account (see
// authn.Service.EnsureDefaultAdmin). On a new install it then opens the
// setup guide for that account; an install whose accounts came from
// auth.db is not new.
func (s *Server) Start(ctx context.Context) error {
	if err := s.firstSteps(ctx); err != nil {
		return err
	}
	err := s.openListeners(ctx)
	if err == nil {
		err = s.startClientAPI(ctx)
	}
	if err != nil {
		s.closeListeners()
		s.net.addr = ""
		if s.cfg.PortUnset && listen.InUse(err) {
			return fmt.Errorf("%w: %w", ErrDefaultPortTaken, err)
		}
		return err
	}
	s.jobs.Start(ctx)
	logging.Logf("console", "listening on %s, %d routes", s.net.addr, len(s.early.Routes())+len(s.router.Routes()))
	return nil
}

// firstSteps are the steps of Start before it listens: the auth.db import,
// the branding, the first account and the setup guide. Instances that
// start together take turns (store.DB.LockInstallation), so only one
// imports and makes the first account.
func (s *Server) firstSteps(ctx context.Context) error {
	unlock, err := s.deps.Store.LockInstallation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	imported, err := authimport.Run(ctx, s.deps.Store, s.authImport)
	if err != nil {
		return fmt.Errorf("auth.db import: %w", err)
	}
	s.deps.Branding.LoadBranding(ctx)
	if _, err := s.deps.Authn.EnsureDefaultAdmin(ctx); err != nil {
		return fmt.Errorf("first account: %w", err)
	}
	if imported == nil {
		if err := s.deps.SetupGuide.Begin(ctx); err != nil {
			logging.Logf("console", "WARN: the setup guide could not be opened for the first admin: %v", err)
		}
	}
	return nil
}

// ErrDefaultPortTaken is the error of Start when CONSOLE_PORT is not set
// and a port of the console is taken: the server then runs without its
// console (DECISIONS A62), as an install whose older console still holds
// the port needs.
var ErrDefaultPortTaken = errors.New("a port of the console is taken and CONSOLE_PORT is not set")

// Addr is the address the server listens on, once started.
func (s *Server) Addr() string {
	return s.net.addr
}

// Stop closes the listeners, gives open requests ten seconds to finish,
// ends the open websockets and the background jobs and waits for the
// profile picture syncs that sign-ins started. When it returns, nothing
// the server started is still running.
func (s *Server) Stop() {
	s.closeListeners()
	s.deps.Sockets.Close()
	s.jobs.Stop()
	s.deps.Avatars.Wait()
}

// readSetting reads one row of the console's settings table, for the
// updater's backup retention (db.getSetting). A NULL value counts as no
// row.
func readSetting(db *store.DB) func(ctx context.Context, key string) (string, bool, error) {
	return func(ctx context.Context, key string) (string, bool, error) {
		if db == nil {
			return "", false, nil
		}
		rows, err := db.Query(ctx, "SELECT value FROM settings WHERE key = ?", key)
		if err != nil {
			return "", false, fmt.Errorf("read setting %s: %w", key, err)
		}
		defer rows.Close()
		if !rows.Next() {
			return "", false, rows.Err()
		}
		var value sql.NullString
		if err := rows.Scan(&value); err != nil {
			return "", false, fmt.Errorf("read setting %s: %w", key, err)
		}
		return value.String, value.Valid, rows.Err()
	}
}

// NeoDesk Server — Clean-room RustDesk-compatible signal + relay server
// Single binary replacing both hbbs and hbbr
package main

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	osSignal "os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/admin"
	"github.com/neodeskapp/neodesk/neodesk-server/api"
	"github.com/neodeskapp/neodesk/neodesk-server/audit"
	"github.com/neodeskapp/neodesk/neodesk-server/auth"
	"github.com/neodeskapp/neodesk/neodesk-server/billing"
	"github.com/neodeskapp/neodesk/neodesk-server/cdap"
	"github.com/neodeskapp/neodesk/neodesk-server/cluster"
	"github.com/neodeskapp/neodesk/neodesk-server/cluster/peerdir"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/console/backup"
	"github.com/neodeskapp/neodesk/neodesk-server/console/updater"
	"github.com/neodeskapp/neodesk/neodesk-server/crypto"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/internal/envvar"
	"github.com/neodeskapp/neodesk/neodesk-server/internal/productversion"
	"github.com/neodeskapp/neodesk/neodesk-server/logging"
	"github.com/neodeskapp/neodesk/neodesk-server/meshcentral"
	"github.com/neodeskapp/neodesk/neodesk-server/metrics"
	"github.com/neodeskapp/neodesk/neodesk-server/ratelimit"
	"github.com/neodeskapp/neodesk/neodesk-server/relay"
	"github.com/neodeskapp/neodesk/neodesk-server/reload"
	"github.com/neodeskapp/neodesk/neodesk-server/security"
	sigServer "github.com/neodeskapp/neodesk/neodesk-server/signal"
	"github.com/neodeskapp/neodesk/neodesk-server/timesync"
)

var (
	Version   = "dev"
	BuildDate = "unknown"
	// Commit is the commit the binary was built from (-X main.Commit=...),
	// empty for a build without one. The updater compares it with a
	// release.
	Commit = ""

	runSQLiteAuthConsolidation       bool
	sqliteAuthConsolidationDryRun    bool
	sqliteAuthConsolidationBackupDir string
	sqliteAuthConsolidationRollback  string
)

type persistedTimeSyncConfig struct {
	NTPServers         string `json:"ntp_servers"`
	MaxSkewMS          int    `json:"max_skew_ms"`
	RequireSyncedClock bool   `json:"require_synced_clock"`
	TrustOSNTP         bool   `json:"trust_os_ntp"`
	BillingTimezone    string `json:"billing_timezone"`
}

// wsOriginNotices are the start's notes on the browser pages the
// WebSocket ports take while no allow list names them: the signal and
// relay ports refuse every page that is not on localhost, the API's event
// stream every page that is not on its own host. Clients without an
// Origin header, such as RustDesk, are not affected. That is the safe
// default, so the notes are debug lines.
func wsOriginNotices(cfg *config.Config) []string {
	var notices []string
	if cfg.AllowedWSOrigins == "" {
		notices = append(notices, "DEBUG: WS_ALLOWED_ORIGINS is not set: the signal and relay WebSocket ports take browser pages from localhost only")
	}
	if cfg.APIAllowedWSOrigins == "" {
		notices = append(notices, "DEBUG: API_WS_ALLOWED_ORIGINS is not set: the API event stream takes browser pages from its own host only")
	}
	return notices
}

// migrateNoteAfter is how long the database's migration runs before the
// start says what it is doing: setting the tables up on the first start
// takes 10 to 30 seconds, an ordinary start well under a second.
const migrateNoteAfter = 3 * time.Second

// migrateSaying runs migrate and, once it has taken longer than after,
// logs that the database's tables are being set up, and how long it took
// when done.
func migrateSaying(migrate func() error, after time.Duration) error {
	start := time.Now()
	done := make(chan struct{})
	noted := make(chan bool, 1)
	go func() {
		select {
		case <-done:
			noted <- false
		case <-time.After(after):
			log.Printf("Database: setting up its tables; the first start takes up to a minute...")
			noted <- true
		}
	}()
	err := migrate()
	close(done)
	if <-noted && err == nil {
		log.Printf("Database: tables ready after %s", time.Since(start).Round(time.Second))
	}
	return err
}

// applySavedCDAPEnabled turns the CDAP gateway on or off as the IoT
// devices page saved it (cdap_enabled). A saved value wins over
// CDAP_ENABLED, which decides only while nothing is saved.
func applySavedCDAPEnabled(cfg *config.Config, database db.Database) {
	saved, err := database.GetConfig("cdap_enabled")
	if err != nil {
		log.Printf("WARN: Failed to read the saved CDAP gateway switch: %v", err)
		return
	}
	if strings.TrimSpace(saved) == "" {
		return
	}
	on, ok := envvar.Switch(saved)
	if !ok {
		log.Printf("WARN: Ignoring the saved CDAP gateway switch %q: not an on/off value", saved)
		return
	}
	if on != cfg.CDAPEnabled {
		state := "off"
		if on {
			state = "on"
		}
		log.Printf("CDAP gateway %s, as saved on the IoT devices page", state)
	}
	cfg.CDAPEnabled = on
}

func applyPersistedTimeSyncConfig(cfg *config.Config, database db.Database) {
	raw, err := database.GetConfig(timesync.PersistedConfigKey)
	if err != nil || strings.TrimSpace(raw) == "" {
		return
	}

	var persisted persistedTimeSyncConfig
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		log.Printf("WARN: Ignoring invalid persisted time-sync configuration: %v", err)
		return
	}
	if strings.TrimSpace(persisted.NTPServers) == "" || persisted.MaxSkewMS <= 0 || persisted.MaxSkewMS > 600000 {
		log.Printf("WARN: Ignoring invalid persisted time-sync configuration values")
		return
	}

	cfg.NTPServers = persisted.NTPServers
	cfg.BillingMaxClockSkewMS = persisted.MaxSkewMS
	cfg.BillingRequireSyncedClock = persisted.RequireSyncedClock
	cfg.BillingTrustOSNTP = persisted.TrustOSNTP
	if tz := strings.TrimSpace(persisted.BillingTimezone); tz != "" {
		if _, err := time.LoadLocation(tz); err == nil {
			cfg.BillingTimezone = tz
		}
	}
	log.Printf("Restored time-sync configuration from DB")
}

func applyPersistedConnectionSettings(cfg *config.Config, database db.Database) {
	raw, err := database.GetConfig(config.PersistedConnectionSettingsKey)
	if err != nil || strings.TrimSpace(raw) == "" {
		return
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		log.Printf("WARN: Ignoring invalid persisted connection configuration: %v", err)
		return
	}
	for _, key := range []string{
		"mode",
		"p2p_fallback_ms",
		"same_nat_relay",
		"allow_shared_nat_initiator",
		"logged_in_only_initiator",
		"operator_only_outbound",
	} {
		if _, ok := fields[key]; !ok {
			log.Printf("WARN: Ignoring incomplete persisted connection configuration: missing %s", key)
			return
		}
	}

	var persisted config.ConnectionSettings
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		log.Printf("WARN: Ignoring invalid persisted connection configuration: %v", err)
		return
	}
	if err := persisted.Validate(); err != nil {
		log.Printf("WARN: Ignoring invalid persisted connection configuration values: %v", err)
		return
	}

	cfg.ApplyConnectionSettings(persisted)
	log.Printf("Restored connection strategy configuration from DB: mode=%s fallback=%dms", persisted.Mode, persisted.P2PFallbackMs)
}

func init() {
	if Version == "dev" {
		if v := productversion.Product(); v != "" && v != "dev" {
			Version = v
		}
	}
}

func main() {
	// Started as neodesk: the command line, not the server
	if code, handled := startedAsCLI(); handled {
		os.Exit(code)
	}
	// Started by the Windows service manager: the server runs until the
	// service is stopped, with its log in a file
	if code, handled := runAsWindowsService(func(stop <-chan struct{}) int {
		loadEnvFileFromOS()
		return serverMain(stop)
	}); handled {
		os.Exit(code)
	}
	// NEODESK_ENV_FILE first: the flags and every setting read the
	// environment it fills
	loadEnvFileFromOS()
	if code, handled := runSubcommand(os.Args[1:]); handled {
		os.Exit(code)
	}
	if code := serverMain(nil); code != 0 {
		os.Exit(code)
	}
}

// serverMain runs the server until SIGINT or SIGTERM, a closed stop (the
// Windows service's stop) or a restart the console asked for, and returns
// the exit status once every part has stopped: updater.ExitRestart after a
// restart request, 0 otherwise.
func serverMain(stop <-chan struct{}) (exitCode int) {
	// The env file gets the settings a new release added, as after the
	// installers' update, also when the console's Updates page installed it
	if !printsOnly(os.Args[1:]) {
		applyEnvDefaultsFromOS()
	}
	// Before anything else: count this start of a freshly installed binary,
	// and put the previous one back when it is the fourth.
	pending := updater.StartupCheck(updater.StartupOptions{
		Args: os.Args[1:], Version: Version, Commit: Commit,
		Logf: func(format string, args ...any) { log.Printf(format, args...) },
	})
	if pending.RolledBack() {
		return updater.ExitRestart
	}

	cfg := parseFlags()
	// exitCode is returned once every deferred stop below has run: a
	// restart the console asked for ends with updater.ExitRestart.

	// Configure log format (must be before any log output)
	logCleanup := logging.Setup(cfg.LogFormat, cfg.LogLevel)
	defer logCleanup()

	if sqliteAuthConsolidationRollback != "" {
		if err := db.RollbackSQLiteAuth(cfg.DBPath, sqliteAuthConsolidationRollback); err != nil {
			logging.Fatalf("SQLite auth consolidation rollback failed: %v", err)
		}
		log.Printf("SQLite auth consolidation rollback completed")
		return
	}
	if runSQLiteAuthConsolidation {
		report, err := migrateSQLiteAuth(context.Background(), cfg.DBPath, cfg.AuthDBPath,
			sqliteAuthConsolidationBackupDir, sqliteAuthConsolidationDryRun)
		if err != nil {
			logging.Fatalf("SQLite auth consolidation failed: %v", err)
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			logging.Fatalf("Encode SQLite auth consolidation report: %v", err)
		}
		fmt.Println(string(encoded))
		return
	}
	// Two listeners on one port: the start stops before anything listens
	if err := checkStartPorts(cfg, os.Getenv); err != nil {
		logging.Fatalf("The start stops: %v", err)
	}

	log.Printf("========================================")
	log.Printf("  NeoDesk Server %s", Version)
	log.Printf("  Build: %s", BuildDate)
	log.Printf("========================================")
	log.Printf("  Mode:       %s", cfg.Mode)
	log.Printf("  Signal:     :%d (UDP+TCP)", cfg.SignalPort)
	log.Printf("  NAT Test:   :%d (TCP)", cfg.SignalPort-1)
	log.Printf("  WS Signal:  :%d (WebSocket)", cfg.SignalPort+2)
	log.Printf("  Relay:      :%d (TCP)", cfg.RelayPort)
	log.Printf("  WS Relay:   :%d (WebSocket)", cfg.RelayPort+2)
	if cfg.APITLSEnabled() {
		log.Printf("  API:        :%d (HTTPS)", cfg.APIPort)
	} else {
		log.Printf("  API:        :%d (HTTP)", cfg.APIPort)
	}
	log.Printf("  Database:   %s", config.RedactedDBPath(cfg.DBPath))
	if cfg.SignalTLSEnabled() {
		log.Printf("  TLS Signal: ENABLED (dual-mode: plain+TLS)")
	}
	if cfg.RelayTLSEnabled() {
		log.Printf("  TLS Relay:  ENABLED (dual-mode: plain+TLS)")
	}
	if cfg.APITLSEnabled() {
		log.Printf("  TLS API:    ENABLED")
		log.Printf("  ⚠ WARNING:  TLS on API port breaks Node.js console (HTTP) and RustDesk client connections!")
		log.Printf("              Only enable --tls-api if ALL consumers use HTTPS.")
		log.Printf("              To fix: remove TLS_API=Y from env or -tls-api from flags.")
	}
	if cfg.HasTLSCert() {
		log.Printf("  TLS Cert:   %s", cfg.TLSCertFile)
		// Validate cert files actually exist — a missing file silently disables TLS
		// without any error, which is a common misconfiguration (e.g. typo in path).
		if _, err := os.Stat(cfg.TLSCertFile); os.IsNotExist(err) {
			log.Printf("  ⚠ WARNING:  TLS certificate file NOT FOUND: %s", cfg.TLSCertFile)
			log.Printf("              TLS_SIGNAL and TLS_RELAY will be silently disabled.")
			log.Printf("              Check TLS_CERT env var or --tls-cert flag for typos.")
		}
		if _, err := os.Stat(cfg.TLSKeyFile); os.IsNotExist(err) {
			log.Printf("  ⚠ WARNING:  TLS key file NOT FOUND: %s", cfg.TLSKeyFile)
			log.Printf("              TLS_SIGNAL and TLS_RELAY will be silently disabled.")
			log.Printf("              Check TLS_KEY env var or --tls-key flag for typos.")
		}
	} else if cfg.TLSSignal || cfg.TLSRelay {
		// User set TLS_SIGNAL=Y or TLS_RELAY=Y but forgot to set cert/key paths
		log.Printf("  ⚠ WARNING:  TLS_SIGNAL=%v TLS_RELAY=%v but TLS_CERT/TLS_KEY are not set.", cfg.TLSSignal, cfg.TLSRelay)
		log.Printf("              Signal and relay will run without TLS. Set TLS_CERT and TLS_KEY env vars.")
	}
	log.Printf("========================================")

	// Load or generate Ed25519 keypair
	kp, err := crypto.LoadOrGenerateKeyPair(cfg.KeyFile)
	if err != nil {
		logging.Fatalf("Failed to initialize keypair: %v", err)
	}
	log.Printf("Server public key: %s", kp.PublicKeyBase64())

	// Valkey before the database: an instance that should share the
	// installation but can't reach Valkey must not touch it
	clusterRT, err := dialCluster(context.Background(), os.Getenv)
	if err != nil {
		logging.Fatalf("The start stops: %v", err)
	}
	defer clusterRT.close()
	startedAt := time.Now()

	// Initialize database
	swapRestoredDatabase(cfg.DBPath)
	moveAsideRustDeskDatabase(cfg.DBPath)
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		logging.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Instances that start together migrate one after the other
	// (PostgreSQL advisory lock; SQLite has one instance)
	if err := cluster.WithMigrationLock(context.Background(), postgresPool(database), func() error {
		if err := migrateSaying(database.Migrate, migrateNoteAfter); err != nil {
			return fmt.Errorf("Failed to run migrations: %w", err)
		}
		// Defensive: ensure client_sessions exists even if an older binary never created it.
		if err := database.EnsureClientSessionsSchema(); err != nil {
			return fmt.Errorf("Failed to ensure client_sessions schema: %w", err)
		}
		return nil
	}); err != nil {
		logging.Fatalf("%v", err)
	}
	applyPersistedTimeSyncConfig(cfg, database)
	applyPersistedConnectionSettings(cfg, database)
	cdapBefore := cfg.CDAPEnabled
	applySavedCDAPEnabled(cfg, database)
	if cfg.CDAPEnabled && !cdapBefore {
		// The gateway's port joins the listeners the start checked
		if err := checkStartPorts(cfg, os.Getenv); err != nil {
			logging.Fatalf("The start stops: %v", err)
		}
	}

	// Load API key from .api_key file or API_KEY env var and sync to database.
	// This ensures the Node.js console and Go server share the same API key
	// even when the server is started without the ALL-IN-ONE install script.
	loadAPIKey(cfg, database)

	// Record this instance; a second one without PostgreSQL and Valkey
	// stops here with what it lacks
	otherInstances, err := clusterRT.join(database, cfg.DBPath, startedAt)
	if err != nil {
		logging.Fatalf("The start stops: %v", err)
	}
	heartbeatCtx, stopHeartbeat := context.WithCancel(context.Background())
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		cluster.Heartbeat(heartbeatCtx, instanceStore{database}, clusterRT.cfg, startedAt)
	}()
	defer func() { stopHeartbeat(); <-heartbeatDone }()
	clusterRT.startLeases(database)

	// Reset all peers to offline on startup (clean slate).
	// Intentionally does NOT write availability_history events so a
	// restart does not flood every device as downtime. Peers that other
	// running instances hold stay as they are; the stale-peer sync
	// clears the ones whose instance died.
	if otherInstances == 0 {
		if err := database.SetAllOffline(); err != nil {
			log.Printf("WARN: Failed to reset peers to offline: %v", err)
		}
	} else {
		log.Printf("[cluster] %d other instance(s) run on this database; peers keep their status", otherInstances)
	}

	// Periodic cleanup for optional availability history.
	go runAvailabilityHistoryCleanup(database, clusterRT.leases)
	go runConnectionSessionCleanup(database, clusterRT.leases)

	log.Printf("Database initialized successfully")

	// The mode saved in the console wins; ENROLLMENT_MODE is the first
	// default, unless ENROLLMENT_MODE_ENV_OVERRIDE=Y forces it.
	envEnrollmentMode := ""
	if cfg.EnrollmentModeFromEnv {
		envEnrollmentMode = cfg.EnrollmentMode
	}
	enrollmentSource, enrollmentModeErr := applyEnrollmentMode(cfg, database)
	if enrollmentModeErr != nil {
		log.Printf("WARN: Failed to reconcile enrollment mode: %v", enrollmentModeErr)
	}
	switch enrollmentSource {
	case "environment":
		log.Printf("Enrollment mode forced by ENROLLMENT_MODE_ENV_OVERRIDE: %s", cfg.EnrollmentMode)
	case "first default":
		log.Printf("Enrollment mode from ENROLLMENT_MODE, saved as the first default: %s", cfg.EnrollmentMode)
	case "database":
		log.Printf("Restored enrollment mode from DB: %s", cfg.EnrollmentMode)
		if envEnrollmentMode != "" && envEnrollmentMode != cfg.EnrollmentMode {
			log.Printf("ENROLLMENT_MODE=%s is not used: the mode saved in the console is %s (ENROLLMENT_MODE_ENV_OVERRIDE=Y forces the variable)",
				envEnrollmentMode, cfg.EnrollmentMode)
		}
	}
	if cfg.EnrollmentMode != "" && cfg.EnrollmentMode != "open" {
		log.Printf("Enrollment restriction active: mode=%s (new devices need token/approval)", cfg.EnrollmentMode)
	}

	// Initialize security modules
	cfg.BlocklistFile = blocklistFile(cfg)
	blocklist, err := openBlocklist(cfg.BlocklistFile, database)
	if err != nil {
		logging.Fatalf("Blocklist: %v", err)
	}

	ipLimiter := ratelimit.NewIPLimiter(
		cfg.SignalRateLimitPerIP,
		config.IPRateLimitWindow,
		config.IPRateLimitCleanup,
	)
	defer ipLimiter.Stop()

	bwLimiter := ratelimit.NewBandwidthLimiter(
		config.DefaultTotalBandwidth,
		config.DefaultSingleBandwidth,
	)

	rateLimitDesc := fmt.Sprintf("%d/min", cfg.SignalRateLimitPerIP)
	if cfg.SignalRateLimitPerIP <= 0 {
		rateLimitDesc = "disabled"
	}
	log.Printf("Security modules initialized (blocklist=%d entries, rate-limit=%s)",
		blocklist.Count(), rateLimitDesc)

	// Initialize JWT manager for API authentication
	jwtSecret, err := loadJWTSecret(database, cfg.JWTSecret)
	if err != nil {
		logging.Fatalf("JWT secret: %v", err)
	}
	jwtExpiry := cfg.JWTExpiry
	if jwtExpiry <= 0 {
		jwtExpiry = 24
	}
	jwtManager := auth.NewJWTManager(jwtSecret, time.Duration(jwtExpiry)*time.Hour)

	// Create initial admin user if no users exist
	userCount, _ := database.UserCount()
	if userCount == 0 {
		adminUser := cfg.InitAdminUser
		if adminUser == "" {
			adminUser = "admin"
		}
		adminPass := initialAdminPassword(cfg.InitAdminPass)
		adminPasswordGenerated := false
		adminPasswordFromFile := false
		if adminPass == "" {
			dbDir := bootstrapCredentialsDir(cfg.DBPath, cfg.KeyFile)
			if existingPass := readBootstrapAdminPassword(dbDir); existingPass != "" {
				adminPass = existingPass
				adminPasswordFromFile = true
			} else {
				adminPass, _ = auth.GenerateRandomString(16)
				adminPasswordGenerated = true
			}
		}
		hash, err := auth.HashPassword(adminPass)
		if err != nil {
			logging.Fatalf("Failed to hash initial admin password: %v", err)
		}
		err = database.CreateUser(&db.User{
			Username:     adminUser,
			PasswordHash: hash,
			Role:         auth.RoleAdmin,
		})
		if err != nil {
			logging.Fatalf("Failed to create initial admin user: %v", err)
		}
		log.Printf("========================================")
		log.Printf("  INITIAL ADMIN CREDENTIALS")
		log.Printf("  Username: %s", adminUser)
		if adminPasswordGenerated {
			dbDir := bootstrapCredentialsDir(cfg.DBPath, cfg.KeyFile)
			credsFile, wrote, err := writeBootstrapAdminCredentials(dbDir, adminUser, adminPass)
			if err != nil {
				logging.Fatalf("Failed to write credentials file: %v", err)
			}
			if wrote {
				log.Printf("  Password: written to %s (mode 0600)", credsFile)
			} else {
				log.Printf("  Password: not written, %s holds another password; set one with the reset-password command", credsFile)
			}
		} else if adminPasswordFromFile {
			log.Printf("  Password: loaded from existing bootstrap credentials file")
		} else {
			log.Print(givenAdminPasswordLine(bootstrapCredentialsDir(cfg.DBPath, cfg.KeyFile), adminPass))
		}
		adminPass = ""
		log.Printf("  (change this password immediately!)")
		log.Printf("========================================")
	}

	// Initialize per-IP relay connection limiter
	var connLimiter *ratelimit.ConnLimiter
	if cfg.RelayMaxConnsIP > 0 {
		connLimiter = ratelimit.NewConnLimiterFromInt(cfg.RelayMaxConnsIP)
		log.Printf("Relay per-IP connection limit: %d", cfg.RelayMaxConnsIP)
	}
	var sessionLimiter *ratelimit.ConnLimiter
	if cfg.RelayMaxConnsIP > 0 {
		sessionLimiter = ratelimit.NewConnLimiterFromInt(cfg.RelayMaxConnsIP)
		log.Printf("Relay active-session per-IP limit: %d", cfg.RelayMaxConnsIP)
	}

	if cfg.EnrollmentMode == config.EnrollmentModeOpen {
		if !cfg.SignalTLSEnabled() || !cfg.RelayTLSEnabled() {
			log.Printf("  ⛔ ERROR [SECURITY]: ENROLLMENT_MODE=open without TLS_SIGNAL and TLS_RELAY — unsafe for Internet-facing production")
		}
	}

	// Initialize audit logger
	auditLogger := openAuditLog(cfg.AuditLogFile, database, clusterRT.leases)
	defer auditLogger.Close()
	auditLogger.Log(audit.ActionServerStart, "system", "", map[string]string{
		"version": Version, "mode": cfg.Mode,
	})
	if cfg.AuditLogFile != "" {
		log.Printf("Audit logging to %s", cfg.AuditLogFile)
	}

	// Initialize metrics collector
	mc := metrics.NewCollector()
	log.Printf("Prometheus metrics available at /metrics")

	// Initialize config reload handler (SIGHUP on Unix, admin command on Windows)
	reloadHandler := reload.NewHandler()
	if cfg.BlocklistFile != "" {
		reloadHandler.OnReload(func() error {
			log.Printf("[reload] Reloading blocklist from %s", cfg.BlocklistFile)
			return blocklist.LoadFromFile(cfg.BlocklistFile)
		})
	}
	reloadHandler.OnReload(func() error { return reloadEnvConfig(cfg, database) })

	// Initialize admin TCP interface
	adminSrv := admin.New(cfg, database, nil, Version) // peer map set per mode
	adminSrv.SetAdminPassword(cfg.AdminPassword)
	adminSrv.SetBlocklist(blocklist)
	adminSrv.SetReloadFunc(reloadHandler.Execute)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The console asks for a restart after a confirmed restart, an update
	// or a restore, when a supervisor starts the process again (DECISIONS
	// A30).
	restartRequested := make(chan struct{}, 1)
	requestRestart := func() {
		select {
		case restartRequested <- struct{}{}:
		default:
		}
	}

	// Time sync + billing (commercialization module)
	timeSyncSvc := timesync.NewService(database, timesync.Config{
		Servers:         cfg.GetNTPServers(),
		Interval:        60 * time.Second,
		QueryTimeout:    5 * time.Second,
		MaxSkew:         time.Duration(cfg.BillingMaxClockSkewMS) * time.Millisecond,
		RequireSync:     cfg.BillingRequireSyncedClock,
		TrustOSNTP:      cfg.BillingTrustOSNTP,
		BillingTimezone: cfg.BillingTimezone,
	})
	log.Printf("[timesync] NTP servers: %v (trust OS NTP when queries fail: %v; billing TZ: %s)",
		cfg.GetNTPServers(), cfg.BillingTrustOSNTP, cfg.BillingLocation().String())
	timeSyncSvc.Start(ctx)
	defer timeSyncSvc.Stop()

	reloadHandler.OnReload(func() error {
		timeSyncSvc.ApplyConfig(timesync.Config{
			Servers:         cfg.GetNTPServers(),
			MaxSkew:         time.Duration(cfg.BillingMaxClockSkewMS) * time.Millisecond,
			RequireSync:     cfg.BillingRequireSyncedClock,
			TrustOSNTP:      cfg.BillingTrustOSNTP,
			BillingTimezone: cfg.BillingTimezone,
		})
		return nil
	})

	billingSvc := billing.NewService(database, timeSyncSvc, cfg.BillingRoundingMinutes, cfg.BillingRequireWorkReport)
	billingSvc.Start(ctx)

	// Start SIGHUP listener in background
	reloadDone := make(chan struct{})
	go reloadHandler.ListenSIGHUP(reloadDone)
	defer close(reloadDone)

	for _, notice := range wsOriginNotices(cfg) {
		log.Print(notice)
	}

	// parseFlags lets only the combined mode through.
	switch cfg.Mode {
	case "all":
		log.Printf("Starting signal + relay + API servers...")
		applySavedPublicRelay(cfg, os.Getenv)
		sig := sigServer.New(cfg, kp, database)
		sig.SetBlocklist(blocklist)
		sig.SetRateLimiter(ipLimiter)
		sig.SetAuditLogger(auditLogger)
		sig.SetBillingService(billingSvc)
		// Several instances share their relay tickets through Valkey, so a
		// ticket issued here can be claimed by the relay of another pod
		var sharedTickets *relay.ValkeyTickets
		if clusterRT.valkey != nil {
			sharedTickets = relay.NewValkeyTickets(clusterRT.valkey.Client, clusterRT.valkey.Prefix())
			defer sharedTickets.Close()
			sig.SetTickets(sharedTickets)
			// Peers registered on other pods, and the calls that reach them
			sig.PeerMap().SetDirectory(peerdir.New(clusterRT.valkey.Client, clusterRT.valkey.Prefix(), clusterRT.cfg.Name), clusterRT.cfg.Name)
			defer sig.PeerMap().Leave()
			if err := clusterRT.startMesh(); err != nil {
				logging.Fatalf("The start stops: %v", err)
			}
			sig.SetCluster(clusterRT.mesh, clusterRT.kv)
		}
		if err := sig.Start(ctx); err != nil {
			logging.Fatalf("Failed to start signal server: %v", err)
		}
		defer sig.Stop()

		relaySrv := relay.New(cfg)
		if sharedTickets != nil {
			relaySrv.SetTicketClaims(sharedTickets)
			relaySrv.SetCluster(clusterRT.mesh, clusterRT.kv)
		}
		clusterRT.relay = relaySrv
		clusterRT.signal = sig
		relaySrv.SetBandwidthLimiter(bwLimiter)
		if connLimiter != nil {
			relaySrv.SetConnLimiter(connLimiter)
		}
		if sessionLimiter != nil {
			relaySrv.SetSessionLimiter(sessionLimiter)
		}
		// The API server comes after the relay; a session that ends
		// before it is there has nobody to tell
		var relayEndedTo atomic.Pointer[api.Server]
		relaySrv.SetSessionReporter(relay.SessionReporterFuncs{
			Started: billingSvc.ActivateRelay,
			Ended: func(uuid string, _ relay.SessionStats) {
				relayEndedTo.Load().RelayEnded(uuid)
				billingSvc.EndRelay(uuid)
				if err := database.EndPeerConnectionSessionByRelay(uuid); err != nil {
					log.Printf("[warn] end connection session for relay %s: %v", uuid, err)
				}
			},
		})
		if err := relaySrv.Start(ctx); err != nil {
			logging.Fatalf("Failed to start relay server: %v", err)
		}
		defer relaySrv.Stop()

		apiSrv := api.New(cfg, database, sig.PeerMap(), relaySrv, Version)
		relayEndedTo.Store(apiSrv)
		defer attachPanelSync(apiSrv, billingSvc, database, cfg.DBPath, cfg.AuthDBPath)()
		attachPanelTrust(apiSrv)
		apiSrv.SetBlocklist(blocklist)
		apiSrv.SetBandwidthLimiter(bwLimiter)
		apiSrv.SetAuditLogger(auditLogger)
		apiSrv.SetEventBus(sig.EventBus())
		apiSrv.SetMetrics(mc)
		apiSrv.SetReadiness(clusterRT.ready)
		apiSrv.SetFleetLease(func() bool { return clusterRT.leases.Held(leaseFleetScheduler) })
		apiSrv.SetJWTManager(jwtManager)
		apiSrv.SetKeyPair(kp)
		apiSrv.SetTimeSyncService(timeSyncSvc)
		apiSrv.SetBillingService(billingSvc)
		vaultKey := cfg.OrgPeerVaultKey
		if vaultKey == "" {
			vaultKey = jwtSecret
		}
		// Device secrets (saved sign-in, organizations' device passwords):
		// their own key file next to the key pair, never in the database or
		// the full backup. ORG_PEER_VAULT_KEY (else the JWT secret) is the old
		// key of organizations' device passwords: rows sealed with it move to
		// the key file now, and it opens nothing else.
		if err := apiSrv.InitDeviceVault(filepath.Dir(cfg.KeyFile)); err != nil {
			log.Printf("[warn] device secrets disabled (saved sign-in, organizations' device passwords): %v", err)
		}
		if err := apiSrv.InitPeerCredentialVault(vaultKey); err != nil {
			log.Printf("[warn] the old key of organizations' device passwords is not usable: %v", err)
		}
		if moved, left, err := apiSrv.MigrateOrgPeerCredentials(); err != nil {
			log.Printf("[warn] moving organizations' device passwords to the key file: %v", err)
		} else if moved > 0 || left > 0 {
			log.Printf("Organizations' device passwords: %d moved to the key file, %d could not be opened with the old key and stay as they were", moved, left)
		}

		if cfg.RemoteTargetVaultKey == "" {
			log.Printf("[warn] remote target credential vault disabled: REMOTE_TARGET_VAULT_KEY is not configured")
		} else if err := apiSrv.InitRemoteTargetCredentialVault(cfg.RemoteTargetVaultKey); err != nil {
			log.Printf("[warn] remote target credential vault disabled: %v", err)
		} else {
			log.Printf("Remote target credential vault ready (AES-GCM)")
		}

		// LDAP provider (loads config from DB, hot-reloadable via API)
		apiSrv.InitLDAP()
		// OIDC/OAuth2 provider (loads config from DB, hot-reloadable via API)
		apiSrv.InitOIDC()

		// CDAP Gateway (optional — custom device automation protocol)
		var cdapGw *cdap.Gateway
		if cfg.CDAPEnabled {
			cdapGw = cdap.New(cfg, database, sig.PeerMap(), sig.EventBus())
			cdapGw.SetBlocklist(blocklist)
			cdapGw.SetAuditLogger(auditLogger)
			cdapGw.SetJWTManager(jwtManager)
			if err := cdapGw.SetSessionGrantPrivateKey(kp.PrivateKey); err != nil {
				logging.Fatalf("Failed to configure CDAP session grant signer: %v", err)
			}
			cdapGw.SetVersion(Version)
			apiSrv.SetCDAPGateway(cdapGw)
		}

		// MeshCentral compatibility layer (optional)
		var meshGw *meshcentral.Gateway
		if cfg.MeshCentralEnabled {
			meshGw, err = meshcentral.NewGateway(cfg, database, sig.PeerMap(), sig.EventBus(), jwtSecret)
			if err != nil {
				logging.Fatalf("Failed to init MeshCentral gateway: %v", err)
			}
			meshGw.SetBlocklist(blocklist)
			meshGw.SetAuditLogger(auditLogger)
			meshGw.SetJWTManager(jwtManager)
			meshGw.SetVersion(Version)
			// Web cert hash: MESH_WEB_CERT_FILE (public TLS agents see, e.g. proxy LE)
			// takes priority over TLS_CERT (may be internal/signal-only).
			webCertPath := cfg.MeshWebCertFile
			if webCertPath == "" {
				webCertPath = cfg.TLSCertFile
			}
			if webCertPath != "" {
				if certBytes, readErr := os.ReadFile(webCertPath); readErr == nil {
					if h := meshcentral.WebCertHash(certBytes); len(h) > 0 {
						meshGw.SetWebCertHash(h)
						log.Printf("[mesh] web cert hash loaded from %s", webCertPath)
					} else {
						log.Printf("[mesh] warning: could not parse web cert at %s — web hash validation skipped", webCertPath)
					}
				} else {
					log.Printf("[mesh] warning: cannot read web cert %s: %v — web hash validation skipped", webCertPath, readErr)
				}
			}
			apiSrv.SetMeshGateway(meshGw)
		}

		apiSrv.SetDerivedClientPort(startDerivedClientPort(cfg, os.Getenv))
		if startConsoleClientAPI() {
			apiSrv.LimitOutside()
			log.Printf("[api] Callers outside this machine and API_ALLOW_FROM get the client API on port %d, as on the console's client API port", cfg.APIPort)
		}
		if err := apiSrv.Start(ctx); err != nil {
			logging.Fatalf("Failed to start API server: %v", err)
		}
		defer apiSrv.Stop()

		if cdapGw != nil {
			if err := cdapGw.Start(ctx); err != nil {
				logging.Fatalf("Failed to start CDAP gateway: %v", err)
			}
			defer cdapGw.Stop()
		}

		if meshGw != nil {
			if err := meshGw.Start(ctx); err != nil {
				logging.Fatalf("Failed to start MeshCentral gateway: %v", err)
			}
			defer meshGw.Stop()
		}

		adminSrv.SetPeerMap(sig.PeerMap())
		if err := adminSrv.Start(ctx); err != nil {
			log.Printf("WARN: Failed to start admin interface: %v", err)
		}
		defer adminSrv.Stop()

		// HttpProxyRequest from clients without an API server setting: the
		// API port's handler, the console's client API port when it runs
		sig.SetAPIProxy(apiSrv.ListenerHandler())
		stopConsole := withoutConsoleOnError(startConsole(ctx, cfg, database, apiSrv, sig.EventBus(), sig.PanelProofForSession, sig.SetControllerFeatures, sig.SetAPIProxy, requestRestart, clusterRT))
		defer stopConsole()

	default:
		logging.Fatal(checkMode(cfg.Mode))
	}

	// Everything listens: a freshly installed binary has made it.
	pending.Ready()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	osSignal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down...", sig)
	case <-stop:
		log.Printf("Service stop requested, shutting down...")
	case <-restartRequested:
		log.Printf("Restart requested, shutting down so that the supervisor starts the server again...")
		exitCode = updater.ExitRestart
		time.AfterFunc(30*time.Second, func() {
			log.Printf("Shutdown took more than 30 seconds, exiting")
			os.Exit(updater.ExitRestart)
		})
	}
	clusterRT.drain()
	cancel()
	log.Printf("Server stopped")
	return exitCode
}

// reloadEnvConfig reads the environment again (SIGHUP, the admin command
// reload) and then puts back what the panel stores over the environment's
// defaults, as the start does.
func reloadEnvConfig(cfg *config.Config, database db.Database) error {
	log.Printf("[reload] Reloading configuration from environment")
	cfg.LoadEnv()
	_, err := applyEnrollmentMode(cfg, database)
	applyPersistedTimeSyncConfig(cfg, database)
	applyPersistedConnectionSettings(cfg, database)
	applySavedCDAPEnabled(cfg, database)
	if err != nil {
		return fmt.Errorf("reconcile enrollment mode: %w", err)
	}
	return nil
}

// resolveEnrollmentMode is config.ResolveEnrollmentMode, which the API's
// read of the mode shares.
func resolveEnrollmentMode(configuredMode, storedMode string, envOverride bool) (string, string) {
	return config.ResolveEnrollmentMode(configuredMode, storedMode, envOverride)
}

// applyEnrollmentMode sets cfg.EnrollmentMode from the mode the database
// holds and the environment, and says where the mode came from:
// "environment" (forced by ENROLLMENT_MODE_ENV_OVERRIDE=Y), "database" (the
// mode saved in the console), "first default" (ENROLLMENT_MODE while the
// database holds none) or "configuration" (the built-in default). A forced
// mode and a first default are stored, so a restart without the variable
// keeps them; the built-in default is not.
func applyEnrollmentMode(cfg *config.Config, database db.Database) (string, error) {
	storedMode, err := database.GetConfig("enrollment_mode")
	if err != nil {
		return "configuration", err
	}

	resolvedMode, source := resolveEnrollmentMode(
		cfg.EnrollmentMode,
		storedMode,
		cfg.EnrollmentModeEnvOverride,
	)
	cfg.EnrollmentMode = resolvedMode
	if source == "configuration" && cfg.EnrollmentModeFromEnv {
		source = "first default"
	}

	if (source == "environment" || source == "first default") && storedMode != resolvedMode {
		if err := database.SetConfig("enrollment_mode", resolvedMode); err != nil {
			return source, err
		}
	}
	return source, nil
}

// openAuditLog is the server's event log: it keeps the events in the
// database for audit.RetentionDays, so the Server events tab has them
// after a restart, and appends them to file when one is named. Only the
// instance that holds the audit-prune lease deletes old events.
func openAuditLog(file string, database db.Database, leases cluster.Leases) *audit.Logger {
	l := audit.NewLogger(file)
	l.UseStoreLeased(database, func() bool { return leases.Held(leaseAuditPrune) })
	return l
}

// withoutConsoleOnError is the console's stop function, or, when the
// console did not start, a stop that does nothing: a console that cannot
// start (a bad file in its settings, for one) is logged and the ID server,
// relay and API go on without it, instead of the whole server stopping
// (L399).
func withoutConsoleOnError(stop func(), err error) func() {
	if err == nil {
		return stop
	}
	log.Printf("ERROR: Failed to start console: %v", err)
	log.Printf("ERROR: the ID server, relay and API keep running without the console. Fix the console's settings and restart the server")
	return func() {}
}

// blocklistFile is the blocklist file the server reads: BLOCKLIST_FILE
// (or -blocklist) when it is set, else blocklist.txt next to the key file,
// the file the console's Advanced tab saves. Without the second, a Docker
// install, which sets no BLOCKLIST_FILE, loaded no entry of the editor
// (L403).
func blocklistFile(cfg *config.Config) string {
	if strings.TrimSpace(cfg.BlocklistFile) != "" {
		return cfg.BlocklistFile
	}
	return filepath.Join(filepath.Dir(cfg.KeyFile), "blocklist.txt")
}

// openBlocklist is the blocklist of the start: the entries of the file,
// when one is named, and the ones kept in the database, where what is
// blocked at run time (an admin's block, Revoke device) goes from then on;
// without them a revoked device could come back after a restart.
func openBlocklist(file string, database db.Database) (*security.Blocklist, error) {
	blocklist := security.NewBlocklist()
	if file != "" {
		if err := blocklist.LoadFromFile(file); err != nil {
			log.Printf("WARN: Failed to load blocklist from %s: %v", file, err)
		}
	}
	if err := blocklist.UseStore(database); err != nil {
		return nil, err
	}
	return blocklist, nil
}

// initialAdminPassword is the password the first account gets from
// INIT_ADMIN_PASS: the given one when it keeps the password rule
// (auth.CheckNewPassword), else "" with an error line, and the account
// gets a made-up password as when none is given.
// givenAdminPasswordLine is the log line on where the first account's
// password is when INIT_ADMIN_PASS gave it. The Docker image makes the
// first password up itself, writes it to .admin_credentials and hands it
// over in INIT_ADMIN_PASS: a given password that file in dir holds is that
// made-up one, not one the admin chose.
func givenAdminPasswordLine(dir, given string) string {
	if given != "" && readBootstrapAdminPassword(dir) == given {
		return "  Password: made up at the first start, in " + filepath.Join(dir, ".admin_credentials") +
			" (neodesk-show-admin-credentials prints it)"
	}
	return "  Password: the one INIT_ADMIN_PASS sets (not logged)"
}

func initialAdminPassword(given string) string {
	if given == "" {
		return ""
	}
	if err := auth.CheckNewPassword(given); err != nil {
		log.Printf("ERROR: INIT_ADMIN_PASS is not used (%v); the first account gets a made-up password", err)
		return ""
	}
	return given
}

// runAvailabilityHistoryCleanup deletes expired peer_availability_events when
// the optional feature is enabled, at the start and every hour.
func runAvailabilityHistoryCleanup(database db.Database, leases cluster.Leases) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	cleanupAvailabilityHistory(database, leases)
	for range ticker.C {
		cleanupAvailabilityHistory(database, leases)
	}
}

// cleanupAvailabilityHistory is one run of runAvailabilityHistoryCleanup;
// an instance that doesn't hold its lease skips it.
func cleanupAvailabilityHistory(database db.Database, leases cluster.Leases) {
	if !leases.Held(leaseAvailabilityCleanup) {
		return
	}
	if !database.IsAvailabilityHistoryEnabled() {
		return
	}
	days := database.AvailabilityHistoryRetentionDays()
	if days <= 0 {
		days = db.DefaultAvailabilityHistoryRetention
	}
	n, err := database.CleanupOldAvailabilityEvents(time.Duration(days) * 24 * time.Hour)
	if err != nil {
		log.Printf("WARN: availability history cleanup: %v", err)
		return
	}
	if n > 0 {
		log.Printf("Availability history cleanup: removed %d events older than %d days", n, days)
	}
}

// runConnectionSessionCleanup deletes old Metrics connection-session rows,
// at the start and every hour.
func runConnectionSessionCleanup(database db.Database, leases cluster.Leases) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	cleanupConnectionSessions(database, leases)
	for range ticker.C {
		cleanupConnectionSessions(database, leases)
	}
}

// cleanupConnectionSessions is one run of runConnectionSessionCleanup; an
// instance that doesn't hold its lease skips it.
func cleanupConnectionSessions(database db.Database, leases cluster.Leases) {
	if !leases.Held(leaseConnectionSessionCleanup) {
		return
	}
	n, err := database.CleanupOldPeerConnectionSessions(
		time.Duration(db.DefaultConnectionSessionRetentionDays) * 24 * time.Hour,
	)
	if err != nil {
		log.Printf("WARN: connection session cleanup: %v", err)
		return
	}
	if n > 0 {
		log.Printf("Connection session cleanup: removed %d rows older than %d days",
			n, db.DefaultConnectionSessionRetentionDays)
	}
}

func ensureScopedAPIKey(database db.Database, apiKey string) error {
	if strings.TrimSpace(apiKey) == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(apiKey))
	hashHex := hex.EncodeToString(hash[:])
	if existing, err := database.GetAPIKeyByHash(hashHex); err == nil && existing != nil {
		return nil
	}
	key := &db.APIKey{
		KeyHash:   hashHex,
		KeyPrefix: apiKey[:min(len(apiKey), 8)],
		Name:      "console-bridge",
		Role:      auth.RoleAdmin,
	}
	return database.CreateAPIKey(key)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// loadJWTSecret returns the secret that signs API tokens: the configured one,
// else the one stored in server_config, so tokens survive restarts. The first
// start makes one and stores it. A stored secret that cannot be read is an
// error, never a reason to make a new one: it is also the key of the peer
// credential vault when ORG_PEER_VAULT_KEY is unset.
func loadJWTSecret(database db.Database, configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	stored, err := database.GetConfig("jwt_secret")
	if err != nil {
		return "", fmt.Errorf("read the stored secret: %w", err)
	}
	if stored != "" {
		return stored, nil
	}
	generated, err := auth.GenerateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("generate: %w", err)
	}
	if err := database.SetConfig("jwt_secret", generated); err != nil {
		return "", fmt.Errorf("store the new secret: %w", err)
	}
	log.Printf("Generated and stored new JWT secret")
	return generated, nil
}

// bootstrapCredentialsDir is the folder of .admin_credentials: the SQLite
// file's folder, or the key file's when the database is PostgreSQL, whose
// DSN names no folder.
func bootstrapCredentialsDir(dbPath, keyFile string) string {
	lower := strings.ToLower(dbPath)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return filepath.Dir(keyFile)
	}
	return filepath.Dir(dbPath)
}

// writeBootstrapAdminCredentials stores the first admin's generated password
// in .admin_credentials. A file that already holds a password is never
// changed; a file without a password line gets the credentials added at its
// end. wrote reports whether the file now holds adminPass.
func writeBootstrapAdminCredentials(dbDir, adminUser, adminPass string) (path string, wrote bool, err error) {
	if dbDir == "" || dbDir == "." {
		dbDir = "."
	}
	credsFile := filepath.Join(dbDir, ".admin_credentials")
	credsContent := fmt.Sprintf(
		"Admin Username: %s\nAdmin Password: %s\n\nChange this password immediately and delete this file!\n",
		adminUser, adminPass,
	)
	file, err := os.OpenFile(credsFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if !os.IsExist(err) {
			return "", false, err
		}
		if existing := readBootstrapAdminPassword(dbDir); existing != "" {
			return credsFile, existing == adminPass, nil
		}
		file, err = os.OpenFile(credsFile, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return "", false, err
		}
		credsContent = "\n" + credsContent
	} else {
		// A new file that could not be written whole is removed.
		defer func() {
			if err != nil {
				_ = os.Remove(credsFile)
			}
		}()
	}
	if _, err = file.WriteString(credsContent); err != nil {
		_ = file.Close()
		return "", false, err
	}
	if err = file.Close(); err != nil {
		return "", false, err
	}
	return credsFile, true, nil
}

func readBootstrapAdminPassword(dbDir string) string {
	if dbDir == "" || dbDir == "." {
		dbDir = "."
	}
	contents, err := os.ReadFile(filepath.Join(dbDir, ".admin_credentials"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if strings.HasPrefix(line, "Admin Password:") {
			password := strings.TrimSpace(strings.TrimPrefix(line, "Admin Password:"))
			if password != "" {
				return password
			}
		}
	}
	return ""
}

func syncAPIKeyToServerConfig(database db.Database, apiKey string) (string, error) {
	existing, _ := database.GetConfig("api_key")
	if existing == apiKey {
		return "unchanged", nil
	}
	if err := database.SetConfig("api_key", apiKey); err != nil {
		return "failed", err
	}
	if existing == "" {
		return "stored", nil
	}
	return "updated", nil
}

func logAPIKeySyncOutcome(source, outcome string, syncErr error) {
	switch outcome {
	case "unchanged":
		log.Printf("API key loaded from %s (already in database)", source)
	case "stored":
		log.Printf("API key loaded from %s and stored in database", source)
	case "updated":
		log.Printf("API key loaded from %s and updated in database", source)
	case "failed":
		if syncErr != nil {
			log.Printf("WARN: Failed to sync API key to server_config: %v", syncErr)
		} else {
			log.Printf("WARN: Failed to sync API key to server_config")
		}
	}
}

// loadAPIKey reads the API key from API_KEY environment variable or .api_key file
// in the key file directory (and DB directory as fallback), and syncs it to the
// database's server_config table. This ensures the Node.js console and Go server
// share the same API key regardless of how the server was started.
func loadAPIKey(cfg *config.Config, database db.Database) {
	var apiKey string
	var source string

	// 1. Check API_KEY environment variable (highest priority)
	if v := os.Getenv("API_KEY"); v != "" {
		apiKey = strings.TrimSpace(v)
		source = "API_KEY env var"
	}

	// 2. Check .api_key file in key file directory
	if apiKey == "" {
		keyDir := filepath.Dir(cfg.KeyFile)
		if keyDir == "" || keyDir == "." {
			keyDir = "."
		}
		apiKeyFile := filepath.Join(keyDir, ".api_key")
		if data, err := os.ReadFile(apiKeyFile); err == nil {
			apiKey = strings.TrimSpace(string(data))
			if apiKey != "" {
				source = ".api_key file (key directory)"
			}
		}
	}

	// 3. Check .api_key file in database directory as fallback
	if apiKey == "" {
		dbDir := filepath.Dir(cfg.DBPath)
		if dbDir == "" || dbDir == "." {
			dbDir = "."
		}
		apiKeyFile := filepath.Join(dbDir, ".api_key")
		if data, err := os.ReadFile(apiKeyFile); err == nil {
			apiKey = strings.TrimSpace(string(data))
			if apiKey != "" {
				source = ".api_key file (database directory)"
			}
		}
	}

	// 4. Check database server_config table (may have been set previously)
	if apiKey == "" {
		if existing, _ := database.GetConfig("api_key"); existing != "" {
			apiKey = existing
			source = "database server_config"
		}
	}

	// 5. Auto-generate if nothing found anywhere
	if apiKey == "" {
		b := make([]byte, 32)
		if _, err := cryptoRand.Read(b); err != nil {
			log.Printf("WARN: Failed to generate API key: %v. Console→Server auth will fail.", err)
			return
		}
		apiKey = hex.EncodeToString(b)
		source = "auto-generated"

		// Write to key file directory so Node.js console can read it
		keyDir := filepath.Dir(cfg.KeyFile)
		if keyDir == "" || keyDir == "." {
			keyDir = "."
		}
		apiKeyFile := filepath.Join(keyDir, ".api_key")
		if err := os.WriteFile(apiKeyFile, []byte(apiKey+"\n"), 0600); err != nil {
			log.Printf("WARN: Auto-generated API key but failed to write .api_key file in key directory: %v", err)
			// Still try to store in DB even if file write fails
		} else {
			log.Printf("Auto-generated API key written to .api_key file in key directory")
		}
	}

	outcome, syncErr := syncAPIKeyToServerConfig(database, apiKey)
	logAPIKeySyncOutcome(source, outcome, syncErr)

	// Always ensure the scoped API key exists in api_keys table.
	// This is critical — authenticateRequest() checks ONLY the api_keys table.
	if err := ensureScopedAPIKey(database, apiKey); err != nil {
		log.Printf("WARN: Failed to migrate API key into scoped api_keys table: %v", err)
	} else {
		log.Printf("API key is available in scoped api_keys table")
	}
}

// resolveAuthDBPath finds legacy console auth.db (SQLite-only deployments).
// PostgreSQL deployments use PanelSyncStore on the primary database instead.
func resolveAuthDBPath(explicit, dbPath string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	candidates := []string{
		"/opt/NeoDeskConsole/data/auth.db",
		"/opt/rustdesk/../NeoDeskConsole/data/auth.db",
	}
	if v := os.Getenv("CONSOLE_DATA_DIR"); v != "" {
		candidates = append(candidates, filepath.Join(v, "auth.db"))
	}
	if v := os.Getenv("DATA_DIR"); v != "" {
		candidates = append(candidates, filepath.Join(v, "auth.db"))
	}
	if v := os.Getenv("NEODESK_AUTH_DB_PATH"); v != "" {
		candidates = append(candidates, v)
	}
	if dbPath != "" && !strings.HasPrefix(dbPath, "postgres") {
		dir := filepath.Dir(dbPath)
		candidates = append(candidates,
			filepath.Join(dir, "auth.db"),
			filepath.Join(dir, "../data/auth.db"),
			filepath.Join(dir, "../../NeoDeskConsole/data/auth.db"),
			filepath.Join(dir, "../NeoDeskConsole/data/auth.db"),
		)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return explicit
}

// attachPanelTrust wires the panel trust bridge (see api/panel_trust.go).
// The secret is optional: without it the bridge stays off and Go only accepts
// its usual JWT / API-key credentials. It is read from the installer-managed
// .env, which the panel updater appends to and never overwrites.
func attachPanelTrust(apiSrv *api.Server) {
	secret := strings.TrimSpace(os.Getenv(api.PanelTrustSecretEnv))
	if secret == "" {
		log.Printf("[panel-trust] DEBUG: disabled (no %s): panel requests use API key auth only", api.PanelTrustSecretEnv)
		return
	}
	if len(secret) < 32 {
		log.Printf("[panel-trust] WARN: %s is shorter than 32 characters; use a generated value", api.PanelTrustSecretEnv)
	}
	apiSrv.SetPanelTrustSecret(secret)
	log.Printf("[panel-trust] enabled for panel-originated requests")
}

// attachPanelSync wires RustDesk group/folder sync to PostgreSQL, the
// consolidated SQLite store, or a legacy auth.db during the migration window.
func attachPanelSync(apiSrv *api.Server, billingSvc *billing.Service, database db.Database, primaryDBPath, authDBPath string) func() {
	if pg, ok := database.(*db.PostgresDB); ok {
		apiSrv.SetPanelStore(pg)
		if billingSvc != nil {
			billingSvc.SetPanelSyncStore(pg)
		}
		log.Printf("RustDesk panel sync: PostgreSQL (device groups, folders, ACL)")
		return func() {}
	}
	if _, ok := database.(*db.SQLiteDB); ok {
		authDBPath = panelSyncPath(primaryDBPath, authDBPath)
	}
	if strings.TrimSpace(authDBPath) == "" {
		log.Printf("WARN: no panel sync source — device groups/folders unavailable to RustDesk client")
		return func() {}
	}
	consoleAuth, err := db.OpenConsoleAuth(authDBPath)
	if err != nil {
		log.Printf("WARN: console auth.db not opened (%s): %v — RustDesk groups from panel may be missing", authDBPath, err)
		return func() {}
	}
	apiSrv.SetPanelStore(consoleAuth)
	if billingSvc != nil {
		billingSvc.SetPanelSyncStore(consoleAuth)
	}
	// panelSyncPath has said so when the sync reads the main file
	if authDBPath != primaryDBPath {
		log.Printf("RustDesk panel sync: legacy auth.db at %s", authDBPath)
	}
	return func() { _ = consoleAuth.Close() }
}

// panelSyncPath is the SQLite file the RustDesk panel sync reads on a
// SQLite install: the main file once auth.db has been moved into it, or
// when there is no auth.db, as the console keeps its tables in the main
// file; else auth.db.
func panelSyncPath(primaryDBPath, authDBPath string) string {
	consolidated, err := db.SQLiteAuthConsolidated(primaryDBPath)
	switch {
	case err != nil:
		log.Printf("WARN: cannot determine SQLite consolidation state: %v", err)
	case consolidated:
		log.Printf("RustDesk panel sync: consolidated SQLite database")
		return primaryDBPath
	case !isFile(authDBPath):
		log.Printf("RustDesk panel sync: main SQLite database, no auth.db")
		return primaryDBPath
	}
	return authDBPath
}

// isFile reports whether path names a file that exists.
func isFile(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// parseFlags is configure on the command line. It prints the version and
// exits for -version, and ends the start on a configuration it refuses.
func parseFlags() *config.Config {
	cfg, showVersion, err := configure(flag.CommandLine, os.Args[1:])
	if err != nil {
		logging.Fatal(err)
	}
	if showVersion {
		// The updater reads this line from a binary it is about to install.
		if Commit != "" {
			fmt.Printf("neodesk-server %s (built %s, commit %s)\n", Version, BuildDate, Commit)
		} else {
			fmt.Printf("neodesk-server %s (built %s)\n", Version, BuildDate)
		}
		os.Exit(0)
	}
	return cfg
}

// configure reads the server's configuration: the defaults, then the
// flags in args, then the environment, which wins over the flags.
// showVersion is set for -version, and the configuration is then the
// defaults with the flags.
func configure(fs *flag.FlagSet, args []string) (cfg *config.Config, showVersion bool, err error) {
	cfg = config.DefaultConfig()

	fs.IntVar(&cfg.SignalPort, "port", cfg.SignalPort, "Signal server port (UDP+TCP)")
	fs.IntVar(&cfg.RelayPort, "relay-port", cfg.RelayPort, "Relay server port (TCP)")
	fs.IntVar(&cfg.APIPort, "api-port", cfg.APIPort, "HTTP API port")
	fs.StringVar(&cfg.Mode, "mode", cfg.Mode, "Server mode: all, the only mode (signal, relay, API and console in one process)")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "Database DSN: SQLite path or postgres://... URI")
	fs.StringVar(&cfg.KeyFile, "key-file", cfg.KeyFile, "Ed25519 key file path (without extension)")
	fs.StringVar(&cfg.RelayServers, "relay-servers", cfg.RelayServers, "Comma-separated relay server addresses")
	fs.StringVar(&cfg.RendezvousServers, "rendezvous-servers", cfg.RendezvousServers, "Comma-separated rendezvous server addresses")
	fs.StringVar(&cfg.Mask, "mask", cfg.Mask, "LAN mask (e.g. 192.168.0.0/24)")
	switchVar(fs, &cfg.AlwaysUseRelay, "always-relay", "Always use relay (skip hole punching)")
	fs.StringVar(&cfg.BlocklistFile, "blocklist", cfg.BlocklistFile, "Path to blocklist file (IP/ID/CIDR entries)")
	fs.StringVar(&cfg.AuditLogFile, "audit-log", cfg.AuditLogFile, "Path to audit log file (JSON lines)")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert", cfg.TLSCertFile, "Path to TLS certificate file")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key", cfg.TLSKeyFile, "Path to TLS key file")
	fs.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "Log format: text (default) or json")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level: error, warn, info (default), debug")
	fs.IntVar(&cfg.AdminPort, "admin-port", cfg.AdminPort, "TCP admin interface port (0 = disabled)")
	fs.StringVar(&cfg.JWTSecret, "jwt-secret", cfg.JWTSecret, "JWT signing secret (auto-generated if empty)")
	fs.IntVar(&cfg.JWTExpiry, "jwt-expiry", cfg.JWTExpiry, "JWT token expiry in hours (default 24)")
	switchVar(fs, &runSQLiteAuthConsolidation, "migrate-sqlite-auth", "Safely consolidate legacy auth.db into the selected SQLite DB, then exit")
	switchVar(fs, &sqliteAuthConsolidationDryRun, "migrate-sqlite-auth-dry-run", "Validate legacy auth.db consolidation without modifying databases")
	fs.StringVar(&sqliteAuthConsolidationBackupDir, "migrate-sqlite-auth-backup-dir", "", "Directory for SQLite auth consolidation backups")
	fs.StringVar(&sqliteAuthConsolidationRollback, "rollback-sqlite-auth", "", "Restore the selected SQLite DB from a consolidation snapshot, then exit")
	fs.StringVar(&cfg.AdminPassword, "admin-password", cfg.AdminPassword, "Password for admin TCP interface")
	switchVar(fs, &cfg.ForceHTTPS, "force-https", "Reject non-TLS API requests")
	switchVar(fs, &cfg.TrustProxy, "trust-proxy", "Trust X-Forwarded-For/X-Real-IP headers from reverse proxy (requires --trusted-proxies)")
	trustedProxiesFlag := fs.String("trusted-proxies", "", "Comma-separated CIDR/IP allowlist of reverse proxies that may set X-Forwarded-* (required with --trust-proxy)")
	fs.IntVar(&cfg.RelayMaxConnsIP, "relay-max-conns-ip", cfg.RelayMaxConnsIP, "Max relay connections per IP (0 = unlimited)")
	fs.IntVar(&cfg.SignalRateLimitPerIP, "signal-rate-limit-per-ip", cfg.SignalRateLimitPerIP, "Max signal registrations per IP per minute (0 = unlimited; raise for large NAT deployments)")
	switchVar(fs, &cfg.SameNATRelay, "same-nat-relay", "Auto-fallback to relay when both peers share the same public IP (avoids NAT hairpin failures)")
	switchVar(fs, &cfg.AllowSharedNATInitiator, "allow-shared-nat-initiator", "Allow PunchHole/RequestRelay when multiple live peers share the initiator public IP without token/udp_port (synthetic shared-nat-initiator; default off)")
	switchVar(fs, &cfg.LoggedInOnlyInitiator, "logged-in-only-initiator", "Require a valid NeoDesk client login token for stock PunchHole/RequestRelay initiators (default off)")
	switchVar(fs, &cfg.OperatorOnlyOutbound, "operator-only-outbound", "Require a valid Admin/Operator client session for stock PunchHole/RequestRelay initiators (default off)")
	switchVar(fs, &cfg.P2PFirst, "p2p-first", "Wait for the target's hole punch before answering the initiator so direct P2P can succeed (disable to always answer immediately)")
	fs.IntVar(&cfg.P2PFallbackMs, "p2p-fallback-ms", cfg.P2PFallbackMs, "Grace period (ms) to wait for the target's PunchHoleSent before sending the relay fallback response (only with --p2p-first)")
	fs.StringVar(&cfg.InitAdminUser, "init-admin-user", cfg.InitAdminUser, "Initial admin username (default: admin)")
	fs.StringVar(&cfg.InitAdminPass, "init-admin-pass", cfg.InitAdminPass, "Initial admin password (auto-generated if empty)")
	switchVar(fs, &cfg.TLSSignal, "tls-signal", "Enable TLS on signal TCP/WS ports (requires --tls-cert and --tls-key)")
	switchVar(fs, &cfg.TLSRelay, "tls-relay", "Enable TLS on relay TCP/WS ports (requires --tls-cert and --tls-key)")
	switchVar(fs, &cfg.TLSApi, "tls-api", "Enable TLS on HTTP API port (requires --tls-cert and --tls-key)")
	fs.IntVar(&cfg.CDAPPort, "cdap-port", cfg.CDAPPort, "CDAP WebSocket gateway port (default 21122)")
	switchVar(fs, &cfg.CDAPEnabled, "cdap", "Enable CDAP gateway for custom devices")
	switchVar(fs, &cfg.CDAPTLS, "tls-cdap", "Enable TLS on CDAP gateway port (requires --tls-cert and --tls-key)")

	version := fs.Bool("version", false, "Show version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, false, err
	}
	if *version {
		return cfg, true, nil
	}
	if *trustedProxiesFlag != "" {
		nets, err := config.ParseTrustedProxies(*trustedProxiesFlag)
		if err != nil {
			return nil, false, fmt.Errorf("invalid --trusted-proxies: %w", err)
		}
		cfg.TrustedProxies = nets
	}

	// The environment wins over the flags, TRUSTED_PROXIES included
	cfg.LoadEnv()
	cfg.AuthDBPath = resolveAuthDBPath(cfg.AuthDBPath, cfg.DBPath)
	cfg.WarnProxyTrustMisconfig()

	cfg.Mode = strings.ToLower(cfg.Mode)
	if err := checkMode(cfg.Mode); err != nil {
		return nil, false, err
	}

	return cfg, false, nil
}

// checkMode says why a server mode cannot start, nil for "all". The relay
// pairs only the connections that the signal server of the same process
// authorized, so the two cannot run in separate processes: MODE=signal and
// MODE=relay are refused.
func checkMode(mode string) error {
	switch mode {
	case "all":
		return nil
	case "signal", "relay":
		return fmt.Errorf("MODE=%s (-mode %s) is not supported: the relay only pairs connections that the signal server of the same process authorized, so signal and relay cannot run apart. Use MODE=all (-mode all), the combined mode that runs signal, relay, API and console together", mode, mode)
	default:
		return fmt.Errorf("invalid mode %q: use MODE=all (-mode all), the combined mode that runs signal, relay, API and console together", mode)
	}
}

// swapRestoredDatabase puts the SQLite file a restore left next to the
// server database in its place, before anything opens the database. A
// PostgreSQL DSN names no file, so there is nothing to swap. A failed swap
// is logged and the server starts on the database it has.
func swapRestoredDatabase(dsn string) {
	lower := strings.ToLower(dsn)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return
	}
	swapped, err := backup.SwapInRestoredDatabase(dsn)
	if err != nil {
		log.Printf("ERROR: restored database not put in place: %v", err)
		return
	}
	if swapped {
		log.Printf("Restored database put in place: %s", dsn)
	}
}

// moveAsideRustDeskDatabase moves a database RustDesk's hbbs left at the
// server's SQLite path out of the way, before anything opens it, and says
// where it went. A failed look or move is logged and the server starts on
// the file as it is.
func moveAsideRustDeskDatabase(dsn string) {
	moved, err := db.MoveAsideRustDeskDatabase(dsn, time.Now())
	if err != nil {
		log.Printf("ERROR: could not check whether %s is RustDesk's database: %v", dsn, err)
		return
	}
	if moved != "" {
		log.Printf("WARN: %s was the database of a RustDesk server (hbbs). It is now %s, and NeoDesk starts with a database of its own. The key pair stays, so clients keep this server: each device comes back when it next connects, in Managed mode under Enrollment requests.", dsn, moved)
	}
}

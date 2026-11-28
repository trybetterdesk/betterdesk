// Package api implements the NeoDesk HTTP REST API server.
// Provides endpoints for peer management, server health, statistics,
// detailed device status, blocklist management, and bandwidth stats.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/audit"
	"github.com/neodeskapp/neodesk/neodesk-server/auth"
	"github.com/neodeskapp/neodesk/neodesk-server/billing"
	"github.com/neodeskapp/neodesk/neodesk-server/cdap"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/crypto"
	"github.com/neodeskapp/neodesk/neodesk-server/crypto/devicevault"
	"github.com/neodeskapp/neodesk/neodesk-server/crypto/peervault"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	eventsModule "github.com/neodeskapp/neodesk/neodesk-server/events"
	"github.com/neodeskapp/neodesk/neodesk-server/meshcentral"
	"github.com/neodeskapp/neodesk/neodesk-server/metrics"
	"github.com/neodeskapp/neodesk/neodesk-server/peer"
	"github.com/neodeskapp/neodesk/neodesk-server/policy/unattended"
	"github.com/neodeskapp/neodesk/neodesk-server/ratelimit"
	"github.com/neodeskapp/neodesk/neodesk-server/relay"
	"github.com/neodeskapp/neodesk/neodesk-server/security"
	"github.com/neodeskapp/neodesk/neodesk-server/timesync"

	"github.com/coder/websocket"
	"golang.org/x/crypto/bcrypt"
)

// peerIDRegexp validates RustDesk peer ID format: 6-16 alphanumeric chars, hyphens, underscores.
// Mirrors the validation in signal/handler.go — must be kept in sync.
var peerIDRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]{6,16}$`)

// configKeyRegexp validates config key names: 1-64 alphanumeric chars, underscores, hyphens, dots.
// Prevents arbitrary key injection into the server_config table.
var configKeyRegexp = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// configKeyIsSecret reports whether a server_config key holds a secret or a
// credential: the token signing secret, private keys, passwords, device
// keys and second-factor secrets, pairing codes, quick support sessions
// and share links. The generic config routes neither answer nor write such
// a key; the routes that own them do.
func configKeyIsSecret(key string) bool {
	k := strings.ToLower(key)
	switch k {
	case "jwt_secret", "api_key", telemetryPrivateKeyConfig:
		return true
	}
	for _, prefix := range []string{"device_totp_secret_", ndMgmtPublicKeyConfigPref, pairingCodePrefix, supportSessionPrefix, "mesh_share_"} {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for _, part := range []string{"password", "secret", "private"} {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// ldapAuthProvider is implemented by *auth.LDAPProvider and test mocks.
type ldapAuthProvider interface {
	IsEnabled() bool
	Authenticate(username, password string) (*auth.LDAPResult, error)
	UpdateConfig(cfg *auth.LDAPConfig)
	TestConnection() error
	Config() auth.LDAPConfig
}

// Server is the HTTP API server.
type Server struct {
	// readiness says whether the pod takes traffic (SetReadiness); nil
	// means always
	readiness atomic.Pointer[func() (bool, string)]
	// deviceChat is the console's handler of a computer's support chat
	// (device_chat.go, L526)
	deviceChat deviceChatHandler
	// outside decides what callers outside this machine get on the API
	// port (outside.go)
	outside   outsideAPI
	cfg       *config.Config
	db        db.Database
	peers     *peer.Map
	relay     *relay.Server
	blocklist *security.Blocklist
	bwLimiter *ratelimit.BandwidthLimiter
	auditLog  *audit.Logger
	// joinUnproved limits the audit entries of refused joins per device
	// (auditJoinUnproved)
	joinUnproved unprovedAudit
	eventBus     *eventsModule.Bus
	metrics      *metrics.Collector
	jwtManager   *auth.JWTManager
	loginLimiter *ratelimit.IPLimiter
	// heartbeatLimiter is the ceiling per source address of the client
	// API's heartbeat and sysinfo calls, heartbeatDeviceLimiter the one per
	// device (L498); see heartbeatsPerAddress.
	heartbeatLimiter       *ratelimit.WindowCounter
	heartbeatDeviceLimiter *ratelimit.WindowCounter
	// heartbeatDropLog is when a drop was last logged, per address and limit
	heartbeatDropMu  sync.Mutex
	heartbeatDropLog map[string]time.Time
	// SECURITY (audit fix M-07, 2026-04-10): rate-limit public enrollment and
	// branding endpoints to deter device-ID enumeration and config probing.
	enrollmentLimiter *ratelimit.IPLimiter
	brandingLimiter   *ratelimit.IPLimiter
	// SECURITY (audit M6, 2026-11-13): the audit write endpoints are public, so
	// they need their own budget or an unauthenticated caller can flood the
	// audit tables. 60/min per IP is far above what a real client fleet sends.
	auditWriteLimiter *ratelimit.IPLimiter
	// Short-code pairing: redeem is public and guessable, so it gets its own budget
	// separate from enrollment (a paired device must not consume the enrollment budget).
	pairingLimiter *ratelimit.IPLimiter
	// onboardMu makes making, spending and pruning join and support codes
	// one step each (onboard_codes.go).
	onboardMu sync.Mutex
	// The single sign-on start routes are public and each call keeps a
	// pending entry for minutes.
	oidcStartLimiter  *ratelimit.IPLimiter
	keyPair           *crypto.KeyPair // Ed25519 keypair for signing
	telemetryPrivate  [32]byte        // X25519 private key for telemetry envelopes
	telemetryPublic   [32]byte        // X25519 public key for telemetry envelopes
	telemetryReady    bool
	secureClientsMu   sync.RWMutex
	secureClientKeys  map[string][32]byte
	cdapGw            *cdap.Gateway        // CDAP gateway (nil if CDAP disabled)
	meshGw            *meshcentral.Gateway // MeshCentral compat (nil if disabled)
	ldapProvider      ldapAuthProvider     // LDAP auth provider (nil if not configured)
	oidcProvider      *auth.OIDCProvider   // OIDC/OAuth2 auth provider (nil if not configured)
	clientTFASessions *tfaSessionStore
	panelStore        db.PanelSyncStore // device groups, folders, ACL (PostgreSQL or legacy auth.db)
	panelTrustSecret  []byte            // HMAC key for panel-originated requests (nil = bridge off)
	panelNonces       *panelNonceCache  // replay window for verified panel statements
	timeSync          *timesync.Service
	billing           *billing.Service
	// peerVault is the old key of organizations' device passwords, derived
	// from ORG_PEER_VAULT_KEY or the JWT secret: it only opens rows sealed
	// before the key file (key id v1), which MigrateOrgPeerCredentials
	// moves to deviceVault at start
	peerVault         *peervault.Vault
	remoteTargetVault *peervault.Vault // Dedicated AES-GCM vault for RDP/VNC credentials
	// deviceVault seals saved sign-in details (device_signin.go) and the
	// device passwords of organizations (org_peer_vault.go) with the key
	// file next to the key pair; nil when that key could not be loaded
	deviceVault *devicevault.Vault
	// signinUses are the sessions that used their saved sign-in
	signinUses signinUses
	// callerUses are the relay sessions whose quick support or unattended
	// caller the server vouched for (support_caller.go,
	// unattended_caller.go), once each, whichever route asks
	callerUses signinUses
	// relayEnded hears of the relay's session ends (unattended_caller.go)
	relayEnded relayEndedHook
	// consoleLogins are the desktop sign-ins through the web console
	// (console_device_login.go)
	consoleLogins consoleLogins
	// consoleAddress is where people reach the console in this process
	// (SetConsoleAddress); nil without one
	consoleAddressMu sync.RWMutex
	consoleAddress   func(host string) string
	// signinLiveFn stands in for the relay's live sessions in tests
	signinLiveFn func(uuid string) (relay.LivePair, bool)
	httpSrv      *http.Server
	// derivedPort is the port a RustDesk client with an empty API server
	// setting calls (the ID server's port minus 2); 0 when the API port is
	// that port or another listener has it (SetDerivedClientPort)
	derivedPort int
	mux         sharedMux // the route table, built once (internal_handler.go)
	wg          sync.WaitGroup
	version     string
	now         func() time.Time // the clock of the export file names
	// fleet is the fleet scheduler's state (fleet_queue.go)
	fleet fleetState
	// admissionNow is the clock of quick support admissions
	// (receiver_admission.go); nil is time.Now. Tests set it.
	admissionNow func() time.Time
}

// SetPanelStore attaches the panel data source for RustDesk group/folder sync.
func (s *Server) SetPanelStore(p db.PanelSyncStore) {
	s.panelStore = p
}

// SetConsoleAuth attaches legacy auth.db access (SQLite deployments without consolidated DB).
func (s *Server) SetConsoleAuth(c *db.ConsoleAuthDB) {
	s.panelStore = c
}

// New creates a new API server.
func New(cfg *config.Config, database db.Database, peerMap *peer.Map, relaySrv *relay.Server, version string) *Server {
	s := &Server{
		cfg:                    cfg,
		db:                     database,
		peers:                  peerMap,
		relay:                  relaySrv,
		version:                version,
		loginLimiter:           ratelimit.NewIPLimiter(5, 5*time.Minute, 10*time.Minute),
		heartbeatLimiter:       ratelimit.NewWindowCounter(heartbeatsPerAddress, time.Minute),
		heartbeatDeviceLimiter: ratelimit.NewWindowCounter(heartbeatsPerDevice, time.Minute),
		heartbeatDropLog:       make(map[string]time.Time),
		enrollmentLimiter:      ratelimit.NewIPLimiter(20, 1*time.Minute, 5*time.Minute), // M-07: 20/min per IP, 5-min block
		brandingLimiter:        ratelimit.NewIPLimiter(60, 1*time.Minute, 5*time.Minute), // M-07: 60/min per IP
		auditWriteLimiter:      ratelimit.NewIPLimiter(60, 1*time.Minute, 5*time.Minute), // M6: public audit writes
		// 10/min per IP: a person redeems once; a script brute-forcing 30 bits would
		// need ~10^7 minutes at this rate.
		pairingLimiter: ratelimit.NewIPLimiter(10, 1*time.Minute, 5*time.Minute),
		// 20/min per IP: a person starts a sign-in a few times at most.
		oidcStartLimiter:  ratelimit.NewIPLimiter(20, 1*time.Minute, 5*time.Minute),
		clientTFASessions: newTFASessionStore(),
		secureClientKeys:  make(map[string][32]byte),
		panelNonces:       newPanelNonceCache(),
		now:               time.Now,
	}
	s.fleet.init()
	return s
}

// rateLimitPublic wraps a public (no-auth) handler with the supplied IP limiter.
// Returns HTTP 429 with a JSON body when the per-IP budget is exhausted.
// Used by audit fix M-07 (enrollment, branding endpoints).
func (s *Server) rateLimitPublic(lim *ratelimit.IPLimiter, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if lim != nil {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			if !lim.Allow(ip) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
				return
			}
		}
		h(w, r)
	}
}

// rateLimitOutside is rateLimitPublic for requests from the listener. The
// console's in-process calls all come from one loopback address, so they
// skip the limiter instead of sharing one budget for every console user.
func (s *Server) rateLimitOutside(lim *ratelimit.IPLimiter, h http.HandlerFunc) http.HandlerFunc {
	limited := s.rateLimitPublic(lim, h)
	return func(w http.ResponseWriter, r *http.Request) {
		if arrivedInternally(r) {
			h(w, r)
			return
		}
		limited(w, r)
	}
}

// metricsGuard enforces the audit fix H-03 access policy for /metrics:
//   - cfg.MetricsPublic=true       => unrestricted (legacy/dev)
//   - cfg.MetricsAllowlist non-empty => caller IP must match one entry
//   - otherwise                      => caller must present a valid bearer/api-key
func (s *Server) metricsGuard(h http.HandlerFunc) http.HandlerFunc {
	allowlist := s.cfg.GetMetricsAllowlist()
	public := s.cfg.MetricsPublic
	return func(w http.ResponseWriter, r *http.Request) {
		if public {
			h(w, r)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if len(allowlist) > 0 && ipInAllowlist(ip, allowlist) {
			h(w, r)
			return
		}
		if arrivedInternally(r) {
			h(w, r)
			return
		}
		// Fall back to standard auth middleware (JWT / API key), for a
		// caller that holds metrics.view.
		s.authMiddleware(s.requirePermission(auth.PermMetricsView, h)).ServeHTTP(w, r)
	}
}

// ipInAllowlist reports whether ip matches any literal IP or CIDR in list.
func ipInAllowlist(ip string, list []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range list {
		if entry == ip {
			return true
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// SetBlocklist sets the blocklist instance for the API server.
func (s *Server) SetBlocklist(bl *security.Blocklist) {
	s.blocklist = bl
}

// SetBandwidthLimiter sets the bandwidth limiter for stats reporting.
func (s *Server) SetBandwidthLimiter(bw *ratelimit.BandwidthLimiter) {
	s.bwLimiter = bw
}

// SetAuditLogger sets the audit logger for recording admin actions.
func (s *Server) SetAuditLogger(al *audit.Logger) {
	s.auditLog = al
}

// SetEventBus sets the event bus for real-time WebSocket push.
func (s *Server) SetEventBus(eb *eventsModule.Bus) {
	s.eventBus = eb
}

// SetReadiness sets what /api/health asks before it answers ok: a pod
// whose Valkey is gone or that is shutting down answers 503 with the
// reason, so a load balancer stops sending it traffic.
func (s *Server) SetReadiness(ready func() (bool, string)) {
	if ready != nil {
		s.readiness.Store(&ready)
	}
}

// SetMetrics sets the Prometheus metrics collector.
func (s *Server) SetMetrics(m *metrics.Collector) {
	s.metrics = m
}

// SetJWTManager sets the JWT manager for auth.
func (s *Server) SetJWTManager(jm *auth.JWTManager) {
	s.jwtManager = jm
}

// InitPeerCredentialVault configures AES-GCM sealing for org peer passwords.
// Prefer dedicated ORG_PEER_VAULT_KEY; callers typically fall back to the JWT secret.
func (s *Server) InitPeerCredentialVault(secret string) error {
	v, err := peervault.New(secret)
	if err != nil {
		return err
	}
	s.peerVault = v
	return nil
}

// InitRemoteTargetCredentialVault configures the dedicated RDP/VNC credential
// vault. Unlike the legacy peer vault, this never falls back to JWT secrets.
func (s *Server) InitRemoteTargetCredentialVault(secret string) error {
	v, err := peervault.New(secret)
	if err != nil {
		return err
	}
	s.remoteTargetVault = v
	return nil
}

// SetKeyPair sets the Ed25519 keypair for the server (used for signing IdPk).
func (s *Server) SetKeyPair(kp *crypto.KeyPair) {
	s.keyPair = kp
	s.initializeTelemetryKeys()
}

// SetCDAPGateway sets the CDAP gateway for serving CDAP REST endpoints and
// gives it the API's permission check for registrations with a password or
// an API key.
func (s *Server) SetCDAPGateway(gw *cdap.Gateway) {
	s.cdapGw = gw
	if gw != nil {
		gw.SetPermissionChecker(s)
	}
}

// SetMeshGateway sets the MeshCentral compatibility gateway and gives it
// the API's permission check for the actions of /control.ashx and the
// enrollment queue for new agents (QueueMeshAgent).
func (s *Server) SetMeshGateway(gw *meshcentral.Gateway) {
	s.meshGw = gw
	if gw != nil {
		gw.SetPermissionChecker(s)
		gw.SetEnrollmentQueue(s)
	}
}

// InitLDAP initializes the LDAP provider from the database configuration.
// Should be called after the database is ready, before Start().
func (s *Server) InitLDAP() {
	cfg := s.loadLDAPConfigFromDB()
	s.ldapProvider = auth.NewLDAPProvider(cfg)
	if cfg.Enabled {
		log.Printf("[LDAP] Provider initialized (host=%s, port=%d, tls=%v)", cfg.Host, cfg.Port, cfg.UseTLS)
	}
}

// InitOIDC initializes the OIDC provider from the database configuration.
// Should be called after the database is ready, before Start().
func (s *Server) InitOIDC() {
	cfg := s.loadOIDCConfigFromDB()
	s.oidcProvider = auth.NewOIDCProvider(cfg)
	if cfg.Enabled {
		log.Printf("[OIDC] Provider initialized (issuer=%s, client_id=%s)", cfg.IssuerURL, cfg.ClientID)
	}
}

// routes registers every route on a new mux. Start and InternalHandler share
// the one that s.mux keeps.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Health and public key are needed for client bootstrap. The health response
	// is deliberately minimal (status + version); the full operational payload
	// lives on /api/health/detail behind the same policy as Prometheus metrics
	// (audit H1, 2026-11-13).
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/health/detail", s.metricsGuard(s.handleHealthDetail))
	mux.HandleFunc("GET /api/server/stats", s.metricsGuard(s.handleServerStats))
	mux.HandleFunc("GET /api/server/pubkey", s.handlePubKey)

	// Peers (permission-based access control)
	mux.HandleFunc("GET /api/peers", s.requirePermission(auth.PermDeviceView, s.handleListPeers))
	mux.HandleFunc("GET /api/peers/{id}", s.requirePermission(auth.PermDeviceView, s.handleGetPeer))
	mux.HandleFunc("DELETE /api/peers/{id}", s.requirePermission(auth.PermDeviceDelete, s.handleDeletePeer))
	mux.HandleFunc("PATCH /api/peers/{id}", s.requirePermission(auth.PermDeviceEdit, s.handleUpdatePeerFields))
	mux.HandleFunc("POST /api/peers/{id}/ban", s.requirePermission(auth.PermDeviceBan, s.handleBanPeer))
	mux.HandleFunc("POST /api/peers/{id}/unban", s.requirePermission(auth.PermDeviceBan, s.handleUnbanPeer))
	mux.HandleFunc("POST /api/peers/{id}/restore", s.requirePermission(auth.PermDeviceDelete, s.handleRestorePeer))
	mux.HandleFunc("GET /api/peers/{id}/reach", s.requirePermission(auth.PermDeviceView, s.handlePeerReach))
	mux.HandleFunc("POST /api/peers/{id}/unblock", s.requirePermission(auth.PermDeviceDelete, s.handleUnblockPeer))
	mux.HandleFunc("POST /api/peers/{id}/change-id", s.requirePermission(auth.PermDeviceChangeID, s.handleChangePeerID))

	// Detailed device status (enhanced in Phase 4).
	//
	// SECURITY (audit M8, 2026-11-13): these handlers used to run with
	// authentication but no permission wrapper, so any valid credential —
	// including a RustDesk client session token — could map the fleet (online
	// peers, status, metrics, linked devices) without `device.view`.
	mux.HandleFunc("GET /api/peers/status/summary", s.requirePermission(auth.PermDeviceView, s.handleStatusSummary))
	mux.HandleFunc("GET /api/peers/online", s.requirePermission(auth.PermDeviceView, s.handleOnlinePeers))
	mux.HandleFunc("GET /api/peers/{id}/status", s.requirePermission(auth.PermDeviceView, s.scopedDevice(s.handlePeerStatus)))
	mux.HandleFunc("GET /api/peers/{id}/metrics", s.requirePermission(auth.PermDeviceView, s.handlePeerMetrics))
	mux.HandleFunc("GET /api/peers/{id}/availability", s.requirePermission(auth.PermDeviceView, s.handlePeerAvailability))
	mux.HandleFunc("GET /api/peers/{id}/connection-sessions", s.requirePermission(auth.PermDeviceView, s.handlePeerConnectionSessions))
	mux.HandleFunc("GET /api/peers/{id}/telemetry", s.requirePermission(auth.PermDeviceView, s.scopedDevice(s.handleGetPeerTelemetry)))
	mux.HandleFunc("POST /api/peers/{id}/telemetry/refresh", s.requirePermission(auth.PermDeviceEdit, s.scopedDevice(s.handleRefreshPeerHardware)))
	mux.HandleFunc("POST /api/peers/{id}/telemetry/command", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleQueuePeerTelemetryCommand)))
	mux.HandleFunc("GET /api/peers/{id}/linked", s.requirePermission(auth.PermDeviceView, s.scopedDevice(s.handleLinkedPeers)))
	mux.HandleFunc("POST /api/peers/{id}/wol", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleWakeOnLan)))
	mux.HandleFunc("GET /api/peers/{id}/access-policy", s.requirePermission(auth.PermDeviceView, s.scopedDevice(s.handleGetAccessPolicy)))
	mux.HandleFunc("PUT /api/peers/{id}/access-policy", s.requireRole(auth.RoleAdmin, s.scopedDevice(s.handleSaveAccessPolicy)))
	mux.HandleFunc("DELETE /api/peers/{id}/access-policy", s.requireRole(auth.RoleAdmin, s.scopedDevice(s.handleDeleteAccessPolicy)))
	mux.HandleFunc("GET /api/peers/{id}/connection-mode", s.requirePermission(auth.PermDeviceView, s.handleGetConnectionMode))
	mux.HandleFunc("POST /api/peers/{id}/connection-mode", s.requirePermission(auth.PermDeviceConnectionMode, s.handleSetConnectionMode))
	mux.HandleFunc("POST /api/peers/{id}/session-grant", s.requirePermission(auth.PermDeviceConnect, s.handleIssueSupportSessionGrant))
	mux.HandleFunc("GET /api/peers/{id}/policy", s.requirePermission(auth.PermDeviceView, s.scopedDevice(s.handleGetPeerPolicy)))

	// Manually configured RDP/VNC targets.
	mux.HandleFunc("GET /api/remote-targets", s.requirePermission(auth.PermRemoteTargetView, s.handleListRemoteTargets))
	mux.HandleFunc("POST /api/remote-targets", s.requirePermission(auth.PermRemoteTargetEdit, s.handleCreateRemoteTarget))
	mux.HandleFunc("POST /api/remote-targets/test", s.requirePermission(auth.PermRemoteTargetTest, s.handleTestRemoteTarget))
	mux.HandleFunc("GET /api/remote-targets/readiness", s.requirePermission(auth.PermRemoteTargetView, s.handleRemoteTargetReadiness))
	mux.HandleFunc("GET /api/remote-targets/{id}/credentials", s.requirePermission(auth.PermRemoteTargetView, s.handleGetRemoteTargetCredentialStatus))
	mux.HandleFunc("PUT /api/remote-targets/{id}/credentials", s.requirePermission(auth.PermRemoteTargetEdit, s.handleSetRemoteTargetCredentials))
	mux.HandleFunc("DELETE /api/remote-targets/{id}/credentials", s.requirePermission(auth.PermRemoteTargetEdit, s.handleClearRemoteTargetCredentials))
	mux.HandleFunc("POST /api/remote-targets/{id}/certificate/accept", s.requirePermission(auth.PermRemoteTargetConnect, s.handleAcceptRemoteTargetCertificate))
	mux.HandleFunc("GET /api/remote-targets/{id}/tunnel", s.requirePermission(auth.PermRemoteTargetConnect, s.handleRemoteTargetTunnel))
	mux.HandleFunc("GET /api/remote-targets/{id}", s.requirePermission(auth.PermRemoteTargetView, s.handleGetRemoteTarget))
	mux.HandleFunc("PATCH /api/remote-targets/{id}", s.requirePermission(auth.PermRemoteTargetEdit, s.handleUpdateRemoteTarget))
	mux.HandleFunc("DELETE /api/remote-targets/{id}", s.requirePermission(auth.PermRemoteTargetDelete, s.handleDeleteRemoteTarget))

	// Blocklist management
	mux.HandleFunc("GET /api/blocklist", s.requirePermission(auth.PermBlocklistEdit, s.handleListBlocklist))
	mux.HandleFunc("POST /api/blocklist", s.requirePermission(auth.PermBlocklistEdit, s.handleAddBlocklist))
	mux.HandleFunc("DELETE /api/blocklist/{entry}", s.requirePermission(auth.PermBlocklistEdit, s.handleRemoveBlocklist))

	// Tags
	mux.HandleFunc("PUT /api/peers/{id}/tags", s.requirePermission(auth.PermDeviceEdit, s.scopedDevice(s.handleSetPeerTags)))
	mux.HandleFunc("GET /api/tags/{tag}/peers", s.requirePermission(auth.PermDeviceView, s.handlePeersByTag))

	// Chat (Support chat or Team chat, A242)
	mux.HandleFunc("GET /api/chat/history/", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatHistory))
	mux.HandleFunc("POST /api/chat/messages", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatSendMessage))
	mux.HandleFunc("POST /api/chat/read", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatMarkRead))
	mux.HandleFunc("GET /api/chat/unread/", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatUnread))
	mux.HandleFunc("GET /api/chat/contacts/", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatContacts))
	mux.HandleFunc("POST /api/chat/groups", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatCreateGroup))
	mux.HandleFunc("GET /api/chat/groups/", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatListGroups))
	mux.HandleFunc("PUT /api/chat/groups/", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatUpdateGroup))
	mux.HandleFunc("DELETE /api/chat/groups/", s.requireAnyPermission([]string{auth.PermChatSupport, auth.PermChatTeam}, s.handleChatDeleteGroup))

	// Organizations — org membership enforced on org-specific routes
	mux.HandleFunc("POST /api/org", s.requirePermission(auth.PermOrgCreate, s.handleCreateOrg))
	mux.HandleFunc("GET /api/org", s.handleListOrgs) // data-scoped in handler
	mux.HandleFunc("GET /api/org/{id}", s.requireOrgMembership("id", s.handleGetOrg))
	mux.HandleFunc("PUT /api/org/{id}", s.requirePermission(auth.PermOrgEdit, s.requireOrgMembership("id", s.handleUpdateOrg)))
	mux.HandleFunc("DELETE /api/org/{id}", s.requirePermission(auth.PermOrgDelete, s.handleDeleteOrg))
	mux.HandleFunc("GET /api/org/{id}/users", s.requireOrgMembership("id", refuseOrgSignIn(s.handleListOrgUsers)))
	mux.HandleFunc("POST /api/org/{id}/users", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleCreateOrgUser)))
	mux.HandleFunc("PUT /api/org/{id}/users/{uid}", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleUpdateOrgUser)))
	mux.HandleFunc("DELETE /api/org/{id}/users/{uid}", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleDeleteOrgUser)))
	mux.HandleFunc("POST /api/org/{id}/invite", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleCreateOrgInvitation)))
	mux.HandleFunc("GET /api/org/{id}/invitations", s.requireOrgMembership("id", refuseOrgSignIn(s.requireOrgManager("id", s.handleListOrgInvitations))))
	mux.HandleFunc("DELETE /api/org/{id}/invitations/{invId}", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleRevokeOrgInvitation)))
	// Redeeming an invitation: the console's /invite page, through the console only
	mux.HandleFunc("POST /api/org-invitations/lookup", s.requireConsoleCaller(s.handleLookupOrgInvitation))
	mux.HandleFunc("POST /api/org-invitations/redeem", s.requireConsoleCaller(s.handleRedeemOrgInvitation))
	mux.HandleFunc("POST /api/org/{id}/devices", s.requirePermission(auth.PermOrgManageDevices, s.requireOrgMembership("id", s.handleAssignOrgDevice)))
	mux.HandleFunc("GET /api/org/{id}/devices", s.requireOrgMembership("id", refuseOrgSignIn(s.handleListOrgDevices)))
	mux.HandleFunc("DELETE /api/org/{id}/devices/{did}", s.requirePermission(auth.PermOrgManageDevices, s.requireOrgMembership("id", s.handleUnassignOrgDevice)))
	mux.HandleFunc("GET /api/org/{id}/settings", s.requireOrgMembership("id", refuseOrgSignIn(s.handleListOrgSettings)))
	mux.HandleFunc("PUT /api/org/{id}/settings", s.requirePermission(auth.PermOrgEdit, s.requireOrgMembership("id", s.handleSetOrgSetting)))
	mux.HandleFunc("GET /api/org/{id}/address-book", s.requireOrgMembership("id", s.handleGetOrgAddressBook))
	mux.HandleFunc("PUT /api/org/{id}/address-book", s.requirePermission(auth.PermOrgEdit, s.requireOrgMembership("id", s.handleSetOrgAddressBook)))
	mux.HandleFunc("GET /api/org/{id}/peer-credentials", s.requireOrgMembership("id", refuseOrgSignIn(s.handleListOrgPeerCredentials)))
	mux.HandleFunc("PUT /api/org/{id}/peer-credentials/{peerId}", s.requirePermission(auth.PermOrgEdit, s.requireOrgMembership("id", s.handleSetOrgPeerCredential)))
	mux.HandleFunc("DELETE /api/org/{id}/peer-credentials/{peerId}", s.requirePermission(auth.PermOrgEdit, s.requireOrgMembership("id", s.handleClearOrgPeerCredential)))
	mux.HandleFunc("GET /api/peers/{id}/connect-password", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleGetPeerConnectPassword)))
	mux.HandleFunc("POST /api/org/login", s.handleOrgLogin) // public — no auth required

	// User-Org Linking
	mux.HandleFunc("GET /api/org/{id}/available-users", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleListAvailableUsers)))
	mux.HandleFunc("POST /api/org/{id}/members", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleLinkUserToOrg)))
	mux.HandleFunc("DELETE /api/org/{id}/members/{userId}", s.requirePermission(auth.PermOrgManageUsers, s.requireOrgMembership("id", s.handleUnlinkUserFromOrg)))

	// Organization Policies (stored as org_settings with policy_ prefix)
	mux.HandleFunc("GET /api/org/{id}/policy", s.requireOrgMembership("id", refuseOrgSignIn(s.handleGetOrgPolicy)))
	mux.HandleFunc("PUT /api/org/{id}/policy/{category}", s.requirePermission(auth.PermOrgEdit, s.requireOrgMembership("id", s.handleSetOrgPolicy)))
	mux.HandleFunc("GET /api/org/{id}/policy/effective/{deviceId}", s.requireOrgMembership("id", refuseOrgSignIn(s.handleGetEffectivePolicy)))
	mux.HandleFunc("GET /api/org/{id}/policy/audit", s.requireOrgMembership("id", refuseOrgSignIn(s.handleGetPolicyAudit)))

	// Audit (audit.view permission required)
	mux.HandleFunc("GET /api/audit/events", s.requirePermission(auth.PermAuditView, s.handleAuditEvents))

	// WebSocket real-time events (audit.view permission required — events stream
	// includes peer/auth/system telemetry intended for audit-capable roles only)
	mux.HandleFunc("GET /api/ws/events", s.requirePermission(auth.PermAuditView, s.handleWSEvents))

	// Config (server.config permission)
	mux.HandleFunc("GET /api/config/{key}", s.requirePermission(auth.PermServerConfig, s.handleGetConfig))
	mux.HandleFunc("PUT /api/config/{key}", s.requirePermission(auth.PermServerConfig, s.handleSetConfig))
	mux.HandleFunc("GET /api/connection/config", s.requirePermission(auth.PermServerConfig, s.handleGetConnectionConfig))
	mux.HandleFunc("PUT /api/connection/config", s.requirePermission(auth.PermServerConfig, s.handleSetConnectionConfig))

	// Auth (public — no auth required, handled by middleware exclusion)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/login/2fa", s.handleLogin2FA)
	mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)

	// RustDesk Client API (same consolidated HTTP port as REST — default :21121).
	// Clients with an explicit API Server URL use that; otherwise some builds
	// fall back to signal_port - 2 (21114).
	mux.HandleFunc("POST /api/login", s.handleClientLogin)
	mux.HandleFunc("GET /api/login-options", s.handleClientLoginOptions)
	mux.HandleFunc("POST /api/oidc/auth", s.rateLimitOutside(s.oidcStartLimiter, s.handleClientOIDCAuth))
	mux.HandleFunc("GET /api/oidc/auth-query", s.handleClientOIDCAuthQuery)
	mux.HandleFunc("GET /api/oidc/callback", s.handleOIDCCallback) // alias; same IdP Redirect URL family
	mux.HandleFunc("POST /api/logout", s.handleClientLogout)
	mux.HandleFunc("GET /api/currentUser", s.handleClientCurrentUser)
	mux.HandleFunc("POST /api/currentUser", s.handleClientCurrentUser)
	mux.HandleFunc("GET /api/ab", s.handleClientAddressBook)
	mux.HandleFunc("POST /api/ab", s.handleClientAddressBook)
	mux.HandleFunc("GET /api/ab/personal", s.handleClientAddressBookPersonal)
	mux.HandleFunc("POST /api/ab/personal", s.handleClientAddressBookPersonal)
	mux.HandleFunc("GET /api/ab/tags", s.handleClientAddressBookTags)

	// RustDesk PRO group endpoint stubs — Flutter clients query these and expect
	// the {total,data,msg} envelope; without them the device list never finishes
	// loading.  We expose empty-but-valid responses so the UI gracefully falls
	// back to address-book mode.  Idea credit: progloto.
	mux.HandleFunc("GET /api/group", s.handleClientGroupList)
	mux.HandleFunc("GET /api/group/get", s.handleClientGroupList)
	mux.HandleFunc("POST /api/group/get", s.handleClientGroupList)
	mux.HandleFunc("GET /api/device-group", s.handleClientGroupList)
	mux.HandleFunc("GET /api/device-group/accessible", s.handleClientGroupList)
	mux.HandleFunc("POST /api/device-group", s.requirePanelAdmin(s.handleDeviceGroupsPost))
	mux.HandleFunc("GET /api/peers/list", s.handleClientGroupPeers)
	mux.HandleFunc("POST /api/peers/list", s.handleClientGroupPeers)

	mux.HandleFunc("POST /api/heartbeat", s.handleClientHeartbeat)
	mux.HandleFunc("POST /api/sysinfo", s.handleClientSysinfo)
	mux.HandleFunc("POST /api/sysinfo_ver", s.handleClientSysinfoVer)
	mux.HandleFunc("GET /api/telemetry/key", s.rateLimitPublic(s.brandingLimiter, s.handleTelemetryKey))

	// RustDesk client compat (Phase A — handlers in client_*.go, mirrored from Node :21121)
	mux.HandleFunc("GET /api/server-key", s.handleServerKey)
	mux.HandleFunc("GET /api/server-key/fingerprint", s.handleServerKeyFingerprint)
	mux.HandleFunc("GET /api/software", s.handleClientSoftware)
	mux.HandleFunc("GET /api/software/client-download-link", s.handleClientSoftwareDownloadLink)
	mux.HandleFunc("GET /api/user/group", s.handleClientUserGroup)
	mux.HandleFunc("GET /api/user-groups", s.requirePermission(auth.PermUserView, s.handleUserGroupsGet))
	mux.HandleFunc("POST /api/user-groups", s.requirePanelAdmin(s.handleUserGroupsPost))
	mux.HandleFunc("GET /api/strategies", s.requirePermission(auth.PermDeviceView, s.handleStrategiesGet))
	mux.HandleFunc("POST /api/strategies", s.requirePanelAdmin(s.handleStrategiesPost))
	mux.HandleFunc("POST /api/strategies/assign", s.requirePanelAdmin(s.handleStrategiesAssign))
	mux.HandleFunc("GET /api/strategies/{guid}", s.requirePermission(auth.PermDeviceView, s.handleStrategiesGetByGUID))
	mux.HandleFunc("PUT /api/strategies/{guid}/status", s.requirePanelAdmin(s.handleStrategiesStatus))
	mux.HandleFunc("DELETE /api/strategies/{guid}", s.requirePanelAdmin(s.handleStrategiesDelete))
	mux.HandleFunc("GET /api/devices", s.requirePermission(auth.PermDeviceView, s.handleProDevicesList))
	mux.HandleFunc("POST /api/devices/{guid}/assign", s.requirePanelAdmin(s.handleProDeviceAssign))
	mux.HandleFunc("POST /api/audit/conn", s.rateLimitPublic(s.auditWriteLimiter, s.handleAuditConnPost))
	mux.HandleFunc("GET /api/audit/conn", s.requirePermission(auth.PermAuditView, s.handleAuditConnGet))
	mux.HandleFunc("POST /api/audit/file", s.rateLimitPublic(s.auditWriteLimiter, s.handleAuditFilePost))
	mux.HandleFunc("GET /api/audit/file", s.requirePermission(auth.PermAuditView, s.handleAuditFileGet))
	mux.HandleFunc("POST /api/audit/alarm", s.rateLimitPublic(s.auditWriteLimiter, s.handleAuditAlarmPost))
	mux.HandleFunc("GET /api/audit/alarm", s.requirePermission(auth.PermAuditView, s.handleAuditAlarmGet))
	mux.HandleFunc("GET /api/audit", s.requirePermission(auth.PermAuditView, s.handleClientAuditSummary))
	mux.HandleFunc("GET /api/peer-key/{id}", s.handlePeerKey)

	// User management (permission-based). Accounts, role permissions, API
	// keys and second factors change only for a signed-in person
	// (requirePerson), never for an API key (L387).
	// RustDesk client calls GET /api/users?accessible&pageSize=100
	// with operator tokens. The _getUsers() result gates the entire group pull —
	// if it fails (403), _getPeers() is never called and the Available Devices
	// tab stays empty. Use a wrapper that detects client requests and returns
	// only the current user before the permission check.
	mux.HandleFunc("GET /api/users", s.handleUsersWithClientFallback)
	mux.HandleFunc("POST /api/users", s.requirePerson(s.requirePermission(auth.PermUserCreate, s.handleCreateUser)))
	mux.HandleFunc("PUT /api/users/{id}", s.requirePerson(s.requirePermission(auth.PermUserEdit, s.handleUpdateUser)))
	mux.HandleFunc("DELETE /api/users/{id}", s.requirePerson(s.requirePermission(auth.PermUserDelete, s.handleDeleteUser)))
	mux.HandleFunc("GET /api/users/{id}/organizations", s.requirePermission(auth.PermUserView, s.handleListUserOrganizations))
	mux.HandleFunc("POST /api/users/{id}/organizations", s.requirePermission(auth.PermOrgManageUsers, s.handleAssignUserToOrg))

	// Roles and permissions (RBAC Phase 52)
	mux.HandleFunc("GET /api/roles", s.requirePermission(auth.PermUserView, s.handleListRoles))
	mux.HandleFunc("GET /api/roles/{role}/permissions", s.requirePermission(auth.PermUserView, s.handleGetRolePermissions))
	mux.HandleFunc("GET /api/role-permissions", s.requirePermission(auth.PermServerConfig, s.handleListRolePermissionOverrides))
	mux.HandleFunc("POST /api/role-permissions", s.requirePerson(s.requirePermission(auth.PermServerConfig, s.handleSetRolePermission)))
	mux.HandleFunc("DELETE /api/role-permissions/{role}/{permission}", s.requirePerson(s.requirePermission(auth.PermServerConfig, s.handleDeleteRolePermission)))

	// TOTP management (admin only)
	mux.HandleFunc("POST /api/users/{id}/totp/setup", s.requirePerson(s.requireRole(auth.RoleAdmin, s.handleSetupTOTP)))
	mux.HandleFunc("POST /api/users/{id}/totp/confirm", s.requirePerson(s.requireRole(auth.RoleAdmin, s.handleConfirmTOTP)))
	mux.HandleFunc("DELETE /api/users/{id}/totp", s.requirePerson(s.requireRole(auth.RoleAdmin, s.handleDisableTOTP)))

	// API key management (server.keys permission)
	mux.HandleFunc("GET /api/keys", s.requirePermission(auth.PermServerKeys, s.handleListAPIKeys))
	mux.HandleFunc("POST /api/keys", s.requirePerson(s.requirePermission(auth.PermServerKeys, s.handleCreateAPIKey)))
	mux.HandleFunc("DELETE /api/keys/{id}", s.requirePerson(s.requirePermission(auth.PermServerKeys, s.handleDeleteAPIKey)))

	// Device token management (Dual Key System - admin only)
	mux.HandleFunc("GET /api/tokens", s.requireRole(auth.RoleAdmin, s.handleListDeviceTokens))
	mux.HandleFunc("POST /api/tokens", s.requireRole(auth.RoleAdmin, s.handleCreateDeviceToken))
	mux.HandleFunc("GET /api/tokens/{id}", s.requireRole(auth.RoleAdmin, s.handleGetDeviceToken))
	mux.HandleFunc("PUT /api/tokens/{id}", s.requireRole(auth.RoleAdmin, s.handleUpdateDeviceToken))
	mux.HandleFunc("DELETE /api/tokens/{id}", s.requireRole(auth.RoleAdmin, s.handleRevokeDeviceToken))
	mux.HandleFunc("POST /api/tokens/generate-bulk", s.requireRole(auth.RoleAdmin, s.handleBulkGenerateTokens))
	mux.HandleFunc("POST /api/tokens/{id}/bind", s.requireRole(auth.RoleAdmin, s.handleBindTokenToPeer))

	// Enrollment mode management (Dual Key System - admin only)
	mux.HandleFunc("GET /api/enrollment/mode", s.requireRole(auth.RoleAdmin, s.handleGetEnrollmentMode))
	mux.HandleFunc("PUT /api/enrollment/mode", s.requireRole(auth.RoleAdmin, s.handleSetEnrollmentMode))

	// Enrollment — device self-registration (public, no auth, rate-limited via M-07)
	mux.HandleFunc("POST /api/devices/register", s.rateLimitPublic(s.enrollmentLimiter, s.handleDeviceRegister))
	mux.HandleFunc("GET /api/devices/register/status", s.rateLimitPublic(s.enrollmentLimiter, s.handleDeviceRegisterStatus))
	// rustdesk --deploy --token <device token>; the handler checks the token
	mux.HandleFunc("POST /api/devices/deploy", s.rateLimitPublic(s.enrollmentLimiter, s.handleDeviceDeploy))
	mux.HandleFunc("POST /api/devices/self/access-policy", s.rateLimitPublic(s.enrollmentLimiter, s.handleDeviceSelfAccessPolicy))
	mux.HandleFunc("POST /api/devices/self/help-request", s.rateLimitPublic(s.enrollmentLimiter, s.handleDeviceSelfHelpRequest))
	mux.HandleFunc("POST /api/devices/self/totp", s.rateLimitPublic(s.enrollmentLimiter, s.handleDeviceSelfTOTP))

	// Help requests — operator panel (raised by agents via CDAP or REST self endpoint)
	mux.HandleFunc("GET /api/help/requests", s.requirePermission(auth.PermChatSupport, s.handleListHelpRequests))
	mux.HandleFunc("POST /api/help/requests", s.requirePermission(auth.PermChatSupport, s.handleCreateHelpRequest))
	mux.HandleFunc("GET /api/help/requests/{id}", s.requirePermission(auth.PermChatSupport, s.handleGetHelpRequest))
	mux.HandleFunc("POST /api/help/requests/{id}/acknowledge", s.requirePermission(auth.PermChatSupport, s.handleAcknowledgeHelpRequest))
	mux.HandleFunc("POST /api/help/requests/{id}/resolve", s.requirePermission(auth.PermChatSupport, s.handleResolveHelpRequest))

	// Panel grouping — device groups, their members and ACL, folders, grants.
	// Go owns these writes (strangler stage P2); the RustDesk client reads the
	// same tables through /api/device-group/accessible and /api/peers/list.
	s.registerPanelGroupRoutes(mux)

	// Panel authorization catalog — the console's single source of section and
	// role-default definitions (strangler stage P3). Every signed-in principal
	// may read it: each role needs it to render its own navigation.
	mux.HandleFunc("GET /api/panel/catalog", s.handlePanelCatalog)

	// Time sync / billing (commercialization)
	mux.HandleFunc("GET /api/timesync/status", s.requirePermission(auth.PermBillingView, s.handleTimeSyncStatus))
	mux.HandleFunc("POST /api/timesync/check", s.requirePermission(auth.PermServerConfig, s.handleTimeSyncCheck))
	mux.HandleFunc("GET /api/timesync/config", s.requirePermission(auth.PermServerConfig, s.handleGetTimeSyncConfig))
	mux.HandleFunc("PUT /api/timesync/config", s.requirePermission(auth.PermServerConfig, s.handleSetTimeSyncConfig))
	mux.HandleFunc("GET /api/billing/check", s.requirePermission(auth.PermDeviceConnect, s.handleBillingConnectionCheck))
	mux.HandleFunc("GET /api/billing/packages", s.requirePermission(auth.PermBillingView, s.handleListBillingPackages))
	mux.HandleFunc("GET /api/billing/packages/{id}/preview", s.requirePermission(auth.PermBillingView, s.handleBillingPackagePreview))
	mux.HandleFunc("POST /api/billing/packages", s.requirePermission(auth.PermBillingManage, s.handleCreateBillingPackage))
	mux.HandleFunc("PUT /api/billing/packages/{id}", s.requirePermission(auth.PermBillingManage, s.handleUpdateBillingPackage))
	mux.HandleFunc("DELETE /api/billing/packages/{id}", s.requirePermission(auth.PermBillingManage, s.handleDeleteBillingPackage))
	mux.HandleFunc("GET /api/billing/contracts", s.requirePermission(auth.PermBillingView, s.handleListBillingContracts))
	mux.HandleFunc("POST /api/billing/contracts", s.requirePermission(auth.PermBillingManage, s.handleCreateBillingContract))
	mux.HandleFunc("PUT /api/billing/contracts/{id}", s.requirePermission(auth.PermBillingManage, s.handleUpdateBillingContract))
	mux.HandleFunc("DELETE /api/billing/contracts/{id}", s.requirePermission(auth.PermBillingManage, s.handleDeleteBillingContract))
	mux.HandleFunc("GET /api/billing/stats", s.requirePermission(auth.PermBillingView, s.handleBillingStats))
	mux.HandleFunc("GET /api/billing/sessions", s.requirePermission(auth.PermBillingView, s.handleListBillingSessions))
	mux.HandleFunc("GET /api/billing/sessions/{id}", s.requirePermission(auth.PermBillingView, s.handleGetBillingSession))
	mux.HandleFunc("GET /api/billing/sessions/pending", s.requirePermission(auth.PermBillingReports, s.handleGetPendingBillingSession))
	mux.HandleFunc("GET /api/billing/sessions/export", s.requirePermission(auth.PermBillingExport, s.handleExportBillingSessions))
	mux.HandleFunc("GET /api/billing/reports", s.requirePermission(auth.PermBillingView, s.handleListBillingReports))
	mux.HandleFunc("GET /api/billing/reports/export", s.requirePermission(auth.PermBillingExport, s.handleExportBillingReports))
	mux.HandleFunc("POST /api/billing/sessions/{id}/report", s.requirePermission(auth.PermBillingReports, s.handleSubmitBillingReport))
	mux.HandleFunc("GET /api/billing/currencies", s.requirePermission(auth.PermBillingView, s.handleListBillingCurrencies))
	mux.HandleFunc("PUT /api/billing/currencies/{code}", s.requirePermission(auth.PermBillingManage, s.handleUpsertBillingCurrency))

	// Enrollment: the pending and history lists and the decisions ask enrollment.approve
	mux.HandleFunc("GET /api/enrollment/pending", s.requirePermission(auth.PermEnrollmentApprove, s.handleListPendingDevices))
	mux.HandleFunc("GET /api/enrollment/history", s.requirePermission(auth.PermEnrollmentApprove, s.handleListEnrollmentHistory))
	mux.HandleFunc("POST /api/enrollment/approve/{id}", s.requirePermission(auth.PermEnrollmentApprove, s.handleApproveDevice))
	mux.HandleFunc("POST /api/enrollment/reject/{id}", s.requirePermission(auth.PermEnrollmentApprove, s.handleRejectDevice))
	mux.HandleFunc("POST /api/enrollment/clear-rejection/{id}", s.requirePermission(auth.PermEnrollmentApprove, s.handleClearEnrollmentRejection))

	// LDAP configuration (server.config permission)
	mux.HandleFunc("GET /api/auth/ldap/config", s.requirePermission(auth.PermServerConfig, s.handleGetLDAPConfig))
	mux.HandleFunc("PUT /api/auth/ldap/config", s.requirePermission(auth.PermServerConfig, s.handleSaveLDAPConfig))
	mux.HandleFunc("POST /api/auth/ldap/test", s.requirePermission(auth.PermServerConfig, s.handleTestLDAPConnection))
	mux.HandleFunc("POST /api/auth/ldap/verify", s.requireConsoleCaller(s.handleLDAPVerifyCredentials))

	// OIDC/OAuth2 configuration (server.config permission)
	mux.HandleFunc("GET /api/auth/oidc/config", s.requirePermission(auth.PermServerConfig, s.handleGetOIDCConfig))
	mux.HandleFunc("PUT /api/auth/oidc/config", s.requirePermission(auth.PermServerConfig, s.handleSaveOIDCConfig))
	mux.HandleFunc("POST /api/auth/oidc/test", s.requirePermission(auth.PermServerConfig, s.handleTestOIDCDiscovery))
	// OIDC public endpoints (no auth — used by login page and IdP callback)
	mux.HandleFunc("GET /api/auth/oidc/status", s.handleOIDCLoginStatus)
	mux.HandleFunc("GET /api/auth/oidc/authorize", s.rateLimitOutside(s.oidcStartLimiter, s.handleOIDCAuthorize))
	mux.HandleFunc("GET /api/auth/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("GET /api/auth/oidc/session", s.handleOIDCSessionRedirect)
	mux.HandleFunc("POST /api/auth/oidc/exchange", s.handleOIDCExchange)

	// Combined SSO status — public, used by Node.js console to detect
	// whether LDAP or OIDC is enabled and auto-provision LDAP-authenticated
	// users on first login.
	mux.HandleFunc("GET /api/auth/sso/status", s.handleSSOStatus)

	// Branding (GET is public for desktop clients, POST is admin)
	mux.HandleFunc("GET /api/branding", s.rateLimitPublic(s.brandingLimiter, s.handleGetBranding))
	mux.HandleFunc("POST /api/branding", s.requireRole(auth.RoleAdmin, s.handleSaveBranding))

	// Short-code pairing (host + 6 characters).
	// Redeem/preview are public because the client has no credentials yet; they are
	// rate-limited and a valid code is required. Minting, listing and revoking ask enrollment.approve.
	mux.HandleFunc("POST /api/pairing/redeem", s.rateLimitPublic(s.pairingLimiter, s.handlePairingRedeem))
	mux.HandleFunc("POST /api/pairing/config", s.rateLimitPublic(s.pairingLimiter, s.handlePairingConfigPreview))
	mux.HandleFunc("POST /api/pairing/codes", s.requirePermission(auth.PermEnrollmentApprove, s.handleCreatePairingCode))
	mux.HandleFunc("GET /api/pairing/codes", s.requirePermission(auth.PermEnrollmentApprove, s.handleListPairingCodes))
	mux.HandleFunc("DELETE /api/pairing/codes/{id}", s.requirePermission(auth.PermEnrollmentApprove, s.handleDeletePairingCode))
	// Join and support codes, for the console in this process only.
	s.onboardRoutes(mux)
	s.connectAnswerRoutes(mux)
	s.signinRoutes(mux)
	s.supportCallerRoutes(mux)
	// Fleet tasks, resources, workflows and compliance (fleet_handlers.go)
	s.fleetRoutes(mux)

	s.consoleLoginRoutes(mux)

	// CDAP device management (requires CDAP gateway to be enabled)
	mux.HandleFunc("GET /api/cdap/status", s.requirePermission(auth.PermCDAPView, s.handleCDAPStatus))
	mux.HandleFunc("GET /api/cdap/devices", s.requirePermission(auth.PermCDAPView, s.handleCDAPListDevices))
	mux.HandleFunc("GET /api/cdap/devices/{id}", s.requirePermission(auth.PermCDAPView, s.scopedDevice(s.handleCDAPDeviceInfo)))
	mux.HandleFunc("GET /api/cdap/devices/{id}/manifest", s.requirePermission(auth.PermCDAPView, s.scopedDevice(s.handleCDAPDeviceManifest)))
	mux.HandleFunc("GET /api/cdap/devices/{id}/state", s.requirePermission(auth.PermCDAPView, s.scopedDevice(s.handleCDAPDeviceState)))
	mux.HandleFunc("POST /api/cdap/devices/{id}/command", s.requirePermission(auth.PermCDAPCommand, s.scopedDevice(s.handleCDAPSendCommand)))
	mux.HandleFunc("GET /api/cdap/alerts", s.requirePermission(auth.PermCDAPView, s.handleCDAPAlerts))

	// CDAP auth delegation (admin only)
	mux.HandleFunc("POST /api/cdap/delegate", s.requireRole(auth.RoleAdmin, s.handleCDAPDelegateCreate))
	mux.HandleFunc("DELETE /api/cdap/delegate/{id}", s.requireRole(auth.RoleAdmin, s.handleCDAPDelegateRevoke))
	mux.HandleFunc("GET /api/cdap/delegations", s.requireRole(auth.RoleAdmin, s.handleCDAPDelegateList))

	// CDAP terminal WebSocket (admin only, upgraded inside handler)
	mux.HandleFunc("GET /api/cdap/devices/{id}/terminal", s.requireRole(auth.RoleAdmin, s.scopedDevice(s.handleCDAPTerminal)))

	// CDAP remote desktop WebSocket (admin only)
	mux.HandleFunc("GET /api/cdap/devices/{id}/desktop", s.requireRole(auth.RoleAdmin, s.scopedDevice(s.handleCDAPDesktop)))

	// CDAP video stream WebSocket (device.connect)
	mux.HandleFunc("GET /api/cdap/devices/{id}/video", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleCDAPVideo)))

	// CDAP file browser WebSocket (admin only)
	mux.HandleFunc("GET /api/cdap/devices/{id}/files", s.requireRole(auth.RoleAdmin, s.scopedDevice(s.handleCDAPFileBrowser)))

	// CDAP audio stream WebSocket (device.connect)
	mux.HandleFunc("GET /api/cdap/devices/{id}/audio", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleCDAPAudio)))

	// MeshCentral compatibility REST
	mux.HandleFunc("GET /api/mesh/server-id", s.requirePermission(auth.PermServerConfig, s.handleMeshServerID))
	mux.HandleFunc("GET /api/mesh/status", s.requirePermission(auth.PermDeviceView, s.handleMeshStatus))
	mux.HandleFunc("GET /api/mesh/groups", s.requirePermission(auth.PermServerConfig, s.handleMeshGroupsList))
	mux.HandleFunc("POST /api/mesh/groups", s.requirePermission(auth.PermServerConfig, s.handleMeshGroupsSave))
	mux.HandleFunc("GET /api/mesh/download.msh", s.requirePermission(auth.PermServerConfig, s.handleMeshDownloadMSH))
	mux.HandleFunc("POST /api/mesh/devices/{id}/desktop", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleMeshDesktopTunnel)))
	mux.HandleFunc("POST /api/mesh/devices/{id}/terminal", s.requirePermission(auth.PermMeshTerminal, s.scopedDevice(s.handleMeshTerminalTunnel)))
	mux.HandleFunc("POST /api/mesh/devices/{id}/files", s.requirePermission(auth.PermMeshFiles, s.scopedDevice(s.handleMeshFilesTunnel)))
	mux.HandleFunc("POST /api/mesh/devices/{id}/share", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleMeshShareCreate)))
	mux.HandleFunc("GET /api/mesh/share/validate", s.handleMeshShareValidate)

	// Guest Access Links (temporary RdClient allowlist links)
	mux.HandleFunc("POST /api/guest/access-links", s.requirePermission(auth.PermGuestCreate, s.handleGuestAccessCreate))
	mux.HandleFunc("GET /api/guest/access-links", s.requirePermission(auth.PermGuestCreate, s.handleGuestAccessList))
	mux.HandleFunc("DELETE /api/guest/access-links/{id}", s.requirePermission(auth.PermGuestCreate, s.handleGuestAccessRevoke))
	mux.HandleFunc("GET /api/guest/access-links/validate", s.handleGuestAccessValidate)
	mux.HandleFunc("POST /api/guest/access-links/consume", s.requirePermission(auth.PermGuestCreate, s.handleGuestAccessConsume))
	mux.HandleFunc("POST /api/guest/access-links/events", s.requirePermission(auth.PermGuestCreate, s.handleGuestAccessEvent))
	mux.HandleFunc("GET /api/guest/access-links/peers", s.handleGuestAccessPeers)
	mux.HandleFunc("POST /api/mesh/devices/{id}/tcp", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleMeshTcpRelay)))
	mux.HandleFunc("POST /api/mesh/devices/{id}/udp", s.requirePermission(auth.PermDeviceConnect, s.scopedDevice(s.handleMeshUdpRelay)))
	mux.HandleFunc("POST /api/mesh/devices/{id}/power", s.requirePermission(auth.PermMeshPower, s.scopedDevice(s.handleMeshPower)))
	mux.HandleFunc("POST /api/mesh/devices/{id}/group", s.requirePermission(auth.PermServerConfig, s.scopedDevice(s.handleMeshDeviceGroup)))
	mux.HandleFunc("GET /api/mesh/recordings", s.requirePermission(auth.PermDeviceView, s.handleMeshRecordingsList))
	mux.HandleFunc("GET /api/mesh/recordings/{id}", s.requirePermission(auth.PermDeviceConnect, s.handleMeshRecordingDownload))
	mux.HandleFunc("GET /api/session/recordings", s.requirePermission(auth.PermDeviceView, s.handleSessionRecordingsList))
	// A command runs on the device like one typed into its terminal, so the
	// exec routes ask the terminal permission of the transport: the mesh
	// route mesh.terminal, the unified route the one of the transport the
	// device is connected over (handleUnifiedPeerExec).
	mux.HandleFunc("POST /api/mesh/devices/{id}/exec", s.requirePermission(auth.PermMeshTerminal, s.scopedDevice(s.handleMeshExec)))
	mux.HandleFunc("POST /api/peers/{id}/exec", s.requireAnyPermission([]string{auth.PermMeshTerminal, auth.PermCDAPTerminal}, s.scopedDevice(s.handleUnifiedPeerExec)))

	if s.meshGw != nil {
		s.meshGw.RegisterRoutes(mux)
	}

	// NeoDesk desktop client management WebSocket (no API key — device auth)
	mux.HandleFunc("GET /ws/nd-mgmt/{device_id}", s.handleNdMgmt)
	// Management REST endpoints: status asks device.view. Send hands the
	// agent any message, so it asks the agent's strongest tool, its
	// terminal, and the device must be in the caller's scope (L388).
	mux.HandleFunc("GET /api/nd/mgmt/{device_id}/status", s.requirePermission(auth.PermDeviceView, s.handleNdMgmtStatus))
	mux.HandleFunc("POST /api/nd/mgmt/{device_id}/send", s.requirePermission(auth.PermAgentTerminal, s.scopedDeviceAt("device_id", s.handleNdMgmtSend)))
	mux.HandleFunc("GET /api/nd/mgmt/connected", s.requirePermission(auth.PermDeviceView, s.handleNdMgmtConnected))

	// Prometheus metrics. Gated via H-03 — see handleMetrics for the actual
	// IP-allowlist / auth check. We register a wrapper here that enforces the
	// policy before any metric data is exposed.
	mux.HandleFunc("GET /metrics", s.metricsGuard(s.handleMetrics))

	// Catch-all: return JSON 404 for unmatched routes.
	// Go's default ServeMux returns HTML which breaks RustDesk (Dart) client parsing.
	// Logs every miss so missing client compatibility endpoints are easy to spot.
	// Diagnostics suggestion credit: progloto.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		ua := r.Header.Get("User-Agent")
		if len(ua) > 80 {
			ua = ua[:80] + "…"
		}
		log.Printf("[api] 404 %s %q from %s ua=%q", r.Method, r.URL.Path, ip, ua)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	})
	return mux
}

// ListenerHandler is what the API's listener serves: a computer's support
// chat, which the console answers (device_chat.go), then the secure
// envelope, the credential check and the routes. The console's client API port
// passes its clients' requests to it in process, each with the client's
// address as RemoteAddr, so the limits per address count each client.
//
// The route table is built on the first call to this method,
// InternalHandler or Start, so call it after the Set and Init methods.
func (s *Server) ListenerHandler() http.Handler {
	return s.deviceChatGate(s.secureEnvelopeMiddleware(s.authMiddleware(s.mux.get(s))))
}

// Start launches the HTTP API server.
func (s *Server) Start(ctx context.Context) error {
	addr := config.ListenAddr(s.cfg.APIPort)
	s.httpSrv = &http.Server{
		Addr:        addr,
		Handler:     s.outsideGate(s.ListenerHandler()),
		ReadTimeout: 10 * time.Second,
		// No WriteTimeout — WebSocket connections need unlimited write time.
		// Individual REST handlers are responsible for their own deadlines.
		IdleTimeout: 120 * time.Second,
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}

	// Enable TLS only if explicitly opted in via --tls-api or --force-https
	useTLS := s.cfg.APITLSEnabled()
	if useTLS {
		tlsCfg, err := config.LoadTLSConfig(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("api: %w", err)
		}
		s.httpSrv.TLSConfig = tlsCfg
	}

	// Bind explicitly so the API port can also accept relay framing from clients
	// whose baked `relay-server` value carries no port (they resolve it to the API
	// port). HTTP and TLS pass through untouched; see sniff_listener.go.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("api: listen %s: %w", addr, err)
	}
	var serveLn net.Listener = ln
	if s.relay != nil {
		serveLn = newProtocolSniffListener(ln, s.relay.ServeConn)
		log.Printf("[api] relay compatibility enabled on %s (portless relay-server clients)", addr)
	}

	s.startFleetScheduler()
	s.startDerivedListener(useTLS)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if useTLS {
			log.Printf("[api] HTTPS listening on %s (TLS enabled)", addr)
			if err := s.httpSrv.ServeTLS(serveLn, "", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("[api] HTTPS server error: %v", err)
			}
		} else {
			log.Printf("[api] HTTP listening on %s", addr)
			if err := s.httpSrv.Serve(serveLn); err != nil && err != http.ErrServerClosed {
				log.Printf("[api] HTTP server error: %v", err)
			}
		}
	}()

	return nil
}

// SetDerivedClientPort names the port a stock RustDesk client calls when
// its API server setting is empty: the ID server's host at the ID
// server's port minus 2 (21114 by default). When the API listens on
// another port, as in Docker (21121), Start serves the API on this port
// too, so such a client's heartbeat and system information arrive.
// 0 turns that off. The caller passes 0 when another listener of this
// process has the port.
func (s *Server) SetDerivedClientPort(port int) {
	if port == s.cfg.APIPort || port <= 0 || port > 65535 {
		port = 0
	}
	s.derivedPort = port
}

// startDerivedListener serves the API on the derived client port as well.
// A port that can't be opened leaves the API on its own port only.
func (s *Server) startDerivedListener(useTLS bool) {
	if s.derivedPort == 0 {
		return
	}
	addr := config.ListenAddr(s.derivedPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[api] RustDesk clients without an API server setting call port %d, which can't be opened (%v); they need the API server set to port %d", s.derivedPort, err, s.cfg.APIPort)
		return
	}
	var serveLn net.Listener = ln
	if s.relay != nil {
		serveLn = newProtocolSniffListener(ln, s.relay.ServeConn)
	}
	log.Printf("[api] Also listening on %s for RustDesk clients without an API server setting", addr)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var err error
		if useTLS {
			err = s.httpSrv.ServeTLS(serveLn, "", "")
		} else {
			err = s.httpSrv.Serve(serveLn)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("[api] Server error on %s: %v", addr, err)
		}
	}()
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop() {
	log.Printf("[api] Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.httpSrv.Shutdown(ctx)
	s.stopFleetScheduler()
	s.wg.Wait()
	log.Printf("[api] Stopped")
}

// --- Middleware ---

// --- Handlers ---

// handleHealth returns a minimal liveness payload.
//
// SECURITY (audit H1, 2026-11-13): `/api/health` used to be public and exposed
// peer counts, relay configuration, clock-sync state and the billing flag — a
// free fleet map for anyone on the Internet. Anonymous callers now get
// `{status, version}` only; the operational detail moved to `/api/server/stats`,
// which is gated by `metricsGuard` (IP allowlist or a valid API key).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if ready := s.readiness.Load(); ready != nil {
		if ok, reason := (*ready)(); !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":  "not ready",
				"reason":  reason,
				"version": s.version,
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.version,
	})
}

// handleHealthDetail serves the full health payload for authorized operators.
// Access is enforced by metricsGuard, same policy as /metrics.
func (s *Server) handleHealthDetail(w http.ResponseWriter, r *http.Request) {
	total, online, _ := s.db.GetPeerCount()
	payload := map[string]any{
		"status":       "ok",
		"version":      s.version,
		"peers_total":  total,
		"peers_online": online,
		"uptime":       time.Since(startTime).String(),
		"tls":          s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "",
	}
	if s.peers != nil {
		peerStats := s.peers.GetStats(config.DegradedThreshold, config.CriticalThreshold)
		payload["peers_in_memory"] = peerStats.Total
		payload["peers_degraded"] = peerStats.Degraded
		payload["peers_critical"] = peerStats.Critical
		payload["peers_udp"] = peerStats.UDP
		payload["peers_tcp"] = peerStats.TCP
		payload["peers_ws"] = peerStats.WS
	}
	if s.relay != nil {
		payload["relay_active_sessions"] = s.relay.ActiveSessions.Load()
	}
	if s.billing != nil {
		payload["billing_pending_relays"] = s.billing.PendingRelayCount()
	}
	if s.timeSync != nil {
		payload["clock_synced"] = s.timeSync.IsSynced()
	}
	if s.cfg != nil {
		connection := s.cfg.ConnectionSettings()
		payload["connection"] = map[string]any{
			"p2p_first":                  connection.P2PFirst,
			"always_use_relay":           connection.AlwaysUseRelay,
			"p2p_fallback_ms":            connection.P2PFallbackMs,
			"same_nat_relay":             connection.SameNATRelay,
			"allow_shared_nat_initiator": connection.AllowSharedNATInitiator,
			"logged_in_only_initiator":   connection.LoggedInOnlyInitiator,
			"operator_only_outbound":     connection.OperatorOnlyOutbound,
			"relay_servers":              s.cfg.RelayServers,
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

// handlePubKey returns the server's Ed25519 public key in base64 format.
// This is the "key" value that RustDesk clients use for E2E encryption verification.
// Public endpoint — no authentication required.
func (s *Server) handlePubKey(w http.ResponseWriter, r *http.Request) {
	if s.keyPair == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Server keypair not initialized",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key":     s.keyPair.PublicKeyBase64(),
		"key_hex": fmt.Sprintf("%x", s.keyPair.PublicKey),
	})
}

func (s *Server) handleServerStats(w http.ResponseWriter, r *http.Request) {
	total, online, _ := s.db.GetPeerCount()
	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)

	peerStats := s.peers.GetStats(config.DegradedThreshold, config.CriticalThreshold)

	stats := map[string]any{
		"version":         s.version,
		"go_version":      runtime.Version(),
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"goroutines":      runtime.NumGoroutine(),
		"memory_alloc_mb": float64(memStats.Alloc) / 1024 / 1024,
		"memory_sys_mb":   float64(memStats.Sys) / 1024 / 1024,
		"peers_total":     total,
		"peers_online":    online,
		"peers_in_memory": s.peers.Count(),
		"uptime":          time.Since(startTime).String(),
		"uptime_seconds":  int(time.Since(startTime).Seconds()),
		// Enhanced status stats from peer map
		"peers_online_live": peerStats.Online,
		"peers_degraded":    peerStats.Degraded,
		"peers_critical":    peerStats.Critical,
		"peers_udp":         peerStats.UDP,
		"peers_tcp":         peerStats.TCP,
		"peers_ws":          peerStats.WS,
		"peers_banned": func() int {
			if n, err := s.db.GetBannedPeerCount(); err == nil {
				return n
			}
			return peerStats.Banned
		}(),
		"peers_disabled":      peerStats.Disabled,
		"avg_uptime_secs":     peerStats.AvgUptimeSecs,
		"avg_beat_age_secs":   peerStats.AvgBeatAge,
		"total_registrations": s.peers.TotalRegistrations(),
		"total_expired":       s.peers.TotalExpired(),
	}

	if s.relay != nil {
		stats["relay_active_sessions"] = s.relay.ActiveSessions.Load()
		stats["relay_total_relayed"] = s.relay.TotalRelayed.Load()
	}

	if s.bwLimiter != nil {
		bwStats := s.bwLimiter.Stats()
		stats["bandwidth_bytes_transferred"] = bwStats.TotalBytesTransferred
		stats["bandwidth_active_sessions"] = bwStats.ActiveSessions
		stats["bandwidth_throttle_hits"] = bwStats.ThrottleHits
	}

	if s.blocklist != nil {
		stats["blocklist_count"] = s.blocklist.Count()
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	// Detect RustDesk client group model request: the Flutter client sends
	// ?accessible=&status=1&pageSize=100 and expects {total,data} envelope
	// with PeerPayload format (status as int, info as nested map).
	// Without this detection, the client gets status:"ONLINE"
	// (string) where it expects int, causing "type 'String' is not a subtype
	// of type 'int?'" error.
	if r.URL.Query().Has("accessible") || r.URL.Query().Has("pageSize") {
		s.handleClientPeersList(w, r)
		return
	}

	includeDeleted := r.URL.Query().Get("include_deleted") == "true"
	limit, offset, paginated := parsePeerListPagination(r)

	// Data scoping: org-scoped users only see their org's devices
	orgID := getOrgIDFromCtx(r)
	username := getUsernameFromCtx(r)
	role := getRoleFromCtx(r)
	needsDeviceACL := username != "" && role != "" &&
		!auth.IsSuperAdminRole(role) && role != auth.RoleGlobalAdmin && role != auth.RoleServerAdmin

	var peers []*db.Peer
	var total int
	var err error
	// When device-group ACL applies, load the full candidate set first so
	// pagination cannot leak peers on later pages from an unscoped DB query.
	if needsDeviceACL {
		if orgID != "" {
			peers, err = s.db.ListPeersForOrg(orgID, includeDeleted)
		} else {
			peers, err = s.db.ListPeers(includeDeleted)
		}
	} else if paginated {
		if orgID != "" {
			peers, total, err = s.db.ListPeersForOrgPaginated(orgID, includeDeleted, limit, offset)
		} else {
			peers, total, err = s.db.ListPeersPaginated(includeDeleted, limit, offset)
		}
	} else if orgID != "" {
		peers, err = s.db.ListPeersForOrg(orgID, includeDeleted)
	} else {
		peers, err = s.db.ListPeers(includeDeleted)
	}
	if err != nil {
		writeInternalError(w, err, "ListPeers")
		return
	}

	if needsDeviceACL {
		peerByID := make(map[string]*db.Peer, len(peers))
		for _, p := range peers {
			if p != nil {
				peerByID[p.ID] = p
			}
		}
		user := s.rustDeskUserForGroups(r, username, role)
		if visible := s.rustDeskVisiblePeerSet(user, role, peerByID); visible != nil {
			filtered := make([]*db.Peer, 0, len(peers))
			for _, p := range peers {
				if p != nil && visible[p.ID] {
					filtered = append(filtered, p)
				}
			}
			peers = filtered
		}
		total = len(peers)
		if paginated {
			start := offset
			if start < 0 {
				start = 0
			}
			if start > len(peers) {
				peers = nil
			} else {
				end := start + limit
				if end > len(peers) {
					end = len(peers)
				}
				peers = peers[start:end]
			}
		}
	}

	// Enrich with live online status and status tier from memory map.
	// Override db.Peer.Status (string) with an int
	// so any RustDesk client that reaches this handler without the
	// ?accessible / ?pageSize detection still receives a valid int.
	type peerResponse struct {
		*db.Peer
		Status        int         `json:"status"`      // 1=active, 0=disabled (overrides db.Peer.Status string)
		StatusText    string      `json:"status_text"` // Original string status for admin panel
		LiveOnline    bool        `json:"live_online"`
		SignalReady   bool        `json:"signal_ready"` // Live signal transport is registered
		LiveStatus    peer.Status `json:"live_status"`
		Platform      string      `json:"platform"`
		CDAPConnected bool        `json:"cdap_connected"`
		MeshConnected bool        `json:"mesh_connected"`
		MeshNodeID    string      `json:"mesh_node_id,omitempty"`
		// KeyRefused: the device came back with another key, which the
		// signal server refuses; it takes no session and is not online.
		KeyRefused bool `json:"key_refused,omitempty"`
		// Blocked: the ID is on the blocklist (device_revoked or
		// device_blocked); the signal server refuses it, so it is not
		// online.
		Blocked string `json:"blocked,omitempty"`
	}

	result := make([]peerResponse, len(peers))
	for i, p := range peers {
		liveOnline := s.peers.IsOnline(p.ID, config.RegTimeout)
		signalReady := liveOnline
		liveStatus := peer.StatusOffline
		keyRefused := s.peers.KeyRefused(p.ID)
		if snap, ok := s.peers.GetSnapshot(p.ID, config.DegradedThreshold, config.CriticalThreshold); ok && !keyRefused {
			liveStatus = snap.Status
		}
		// NeoDesk clients may be reachable through the HTTP heartbeat API
		// without a UDP/WebSocket signal entry. Use the recent DB heartbeat as
		// the liveness source in that case.
		if !liveOnline && !keyRefused && !p.LastOnline.IsZero() && time.Since(p.LastOnline) <= config.RegTimeout {
			liveOnline = true
			liveStatus = peer.StatusOnline
		}

		// CDAP overlay: device connected via CDAP gateway is online
		cdapConnected := s.cdapGw != nil && s.cdapGw.IsConnected(p.ID)
		if cdapConnected && !liveOnline {
			liveOnline = true
			liveStatus = peer.StatusOnline
		}
		meshConnected := s.meshGw != nil && s.meshGw.IsConnected(p.ID)
		if meshConnected && !liveOnline {
			liveOnline = true
			liveStatus = peer.StatusOnline
		}
		// Online by a recent heartbeat or an agent without a live signal
		// entry: the signal server may still refuse its key (L452)
		if liveOnline && !signalReady && s.keyRefused(p.ID) {
			keyRefused, liveOnline, liveStatus = true, false, peer.StatusOffline
		}
		blocked := s.blockedReason(p.ID)
		if blocked != "" {
			liveOnline, signalReady, liveStatus = false, false, peer.StatusOffline
		}
		meshNodeID := ""
		if s.meshGw != nil {
			meshNodeID = s.meshGw.MeshNodeID(p.ID)
		}

		statusInt := 1
		if p.Disabled {
			statusInt = 0
		}

		result[i] = peerResponse{
			Peer:          p,
			Status:        statusInt,
			StatusText:    p.Status,
			LiveOnline:    liveOnline,
			SignalReady:   signalReady,
			LiveStatus:    liveStatus,
			Platform:      p.OS,
			CDAPConnected: cdapConnected,
			MeshConnected: meshConnected,
			MeshNodeID:    meshNodeID,
			KeyRefused:    keyRefused,
			Blocked:       blocked,
		}
	}

	if paginated {
		writeJSON(w, http.StatusOK, map[string]any{
			"total": total,
			"data":  result,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func parsePeerListPagination(r *http.Request) (limit, offset int, paginated bool) {
	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		limitStr = r.URL.Query().Get("page_size")
	}
	if limitStr == "" {
		return 0, 0, false
	}
	limit, _ = strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	return limit, (page - 1) * limit, true
}

// handleClientPeersList returns peers in the {total,data} envelope format
// expected by the RustDesk Flutter client's group model.  The PeerPayload
// format requires:
//   - status: int (1=active, 0=disabled) — NOT the string "ONLINE"/"OFFLINE"
//   - info: map with device_name, os, username — NOT flat hostname/os fields
//   - user: string (owner username)
//   - user_name: string (display name)
//
// The client failed with "type 'String' is not a subtype of type 'int?'"
// when the admin API returned status as a string.
func (s *Server) handleClientPeersList(w http.ResponseWriter, r *http.Request) {
	data, total := s.buildRustDeskPeerList(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"total": total,
		"data":  data,
	})
}

func (s *Server) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Org scope check: org-scoped users can only access devices in their org.
	if !s.deviceInScope(w, r, id) {
		return
	}

	p, err := s.db.GetPeer(id)
	if err != nil {
		writeInternalError(w, err, "GetPeer")
		return
	}
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Peer not found"})
		return
	}

	// Enrich with live status from memory map (same as handleListPeers)
	liveOnline := s.peers.IsOnline(p.ID, config.RegTimeout)
	liveStatus := peer.StatusOffline
	keyRefused := s.peers.KeyRefused(p.ID)
	if snap, ok := s.peers.GetSnapshot(p.ID, config.DegradedThreshold, config.CriticalThreshold); ok && !keyRefused {
		liveStatus = snap.Status
	}
	if !liveOnline && !keyRefused && !p.LastOnline.IsZero() && time.Since(p.LastOnline) <= config.RegTimeout {
		liveOnline = true
		liveStatus = peer.StatusOnline
	}

	// CDAP overlay
	cdapConnected := s.cdapGw != nil && s.cdapGw.IsConnected(p.ID)
	if cdapConnected && !liveOnline {
		liveOnline = true
		liveStatus = peer.StatusOnline
	}
	meshConnected := s.meshGw != nil && s.meshGw.IsConnected(p.ID)
	if meshConnected && !liveOnline {
		liveOnline = true
		liveStatus = peer.StatusOnline
	}
	// Online without a live signal entry: the signal server may still
	// refuse its key (L452)
	if liveOnline && !s.peers.IsOnline(p.ID, config.RegTimeout) && s.keyRefused(p.ID) {
		keyRefused, liveOnline, liveStatus = true, false, peer.StatusOffline
	}
	blocked := s.blockedReason(p.ID)
	if blocked != "" {
		liveOnline, liveStatus = false, peer.StatusOffline
	}
	meshNodeID := ""
	if s.meshGw != nil {
		meshNodeID = s.meshGw.MeshNodeID(p.ID)
	}

	type singlePeerResponse struct {
		*db.Peer
		Status        int         `json:"status"`      // 1=active, 0=disabled (overrides db.Peer.Status string)
		StatusText    string      `json:"status_text"` // Original string status for admin panel
		LiveOnline    bool        `json:"live_online"`
		SignalReady   bool        `json:"signal_ready"` // Live signal transport is registered
		LiveStatus    peer.Status `json:"live_status"`
		Platform      string      `json:"platform"`
		CDAPConnected bool        `json:"cdap_connected"`
		MeshConnected bool        `json:"mesh_connected"`
		MeshNodeID    string      `json:"mesh_node_id,omitempty"`
		KeyRefused    bool        `json:"key_refused,omitempty"`
		Blocked       string      `json:"blocked,omitempty"`
		// KeyRequest is a new key the device brought to an invite,
		// which an administrator approves (device_key.go)
		KeyRequest map[string]any `json:"key_request,omitempty"`
	}

	statusInt := 1
	if p.Disabled {
		statusInt = 0
	}
	signalReady := s.peers.IsOnline(p.ID, config.RegTimeout) && blocked == ""

	writeJSON(w, http.StatusOK, singlePeerResponse{
		Peer:          p,
		Status:        statusInt,
		StatusText:    p.Status,
		LiveOnline:    liveOnline,
		SignalReady:   signalReady,
		LiveStatus:    liveStatus,
		Platform:      p.OS,
		CDAPConnected: cdapConnected,
		MeshConnected: meshConnected,
		MeshNodeID:    meshNodeID,
		KeyRefused:    keyRefused,
		Blocked:       blocked,
		KeyRequest:    s.keyRequestOf(p.ID),
	})
}

// handleLinkedPeers returns all peers linked to the given peer ID.
// GET /api/peers/{id}/linked
func (s *Server) handleLinkedPeers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	linked, err := s.db.GetLinkedPeers(id)
	if err != nil {
		writeInternalError(w, err, "GetLinkedPeers")
		return
	}
	if linked, err = s.visiblePeers(r, linked); err != nil {
		writeInternalError(w, err, "device scope")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id": id,
		"linked":  linked,
		"total":   len(linked),
	})
}

// handleUpdatePeerFields partially updates a peer's editable fields (note,
// user, tags, display_name, and linked_peer_id, the peer it is linked to;
// "" removes the link).
// PATCH /api/peers/{id}
func (s *Server) handleUpdatePeerFields(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.deviceInScope(w, r, id) {
		return
	}

	var body struct {
		Note *string `json:"note"`
		User *string `json:"user"`
		// Tags is a text or a list of texts, as PUT /api/peers/{id}/tags
		// takes them
		Tags         json.RawMessage `json:"tags"`
		DisplayName  *string         `json:"display_name"`
		LinkedPeerID *string         `json:"linked_peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	fields := make(map[string]string)
	if body.Note != nil {
		fields["note"] = *body.Note
	}
	if body.User != nil {
		fields["user"] = *body.User
	}
	if len(body.Tags) > 0 && string(body.Tags) != "null" {
		tags, ok := tagsText(body.Tags)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
			return
		}
		fields["tags"] = tags
	}
	if body.DisplayName != nil {
		fields["display_name"] = *body.DisplayName
	}
	if body.LinkedPeerID != nil {
		fields["linked_peer_id"] = *body.LinkedPeerID
	}

	if len(fields) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No fields to update"})
		return
	}

	if err := s.db.UpdatePeerFields(id, fields); err != nil {
		writeInternalError(w, err, "UpdatePeerFields")
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerUpdated, s.eventActor(r), id, nil)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "id": id})
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.deviceInScope(w, r, id) {
		return
	}
	hard := r.URL.Query().Get("hard") == "true"
	revoke := r.URL.Query().Get("revoke") == "true"
	cascade := r.URL.Query().Get("cascade") == "true"

	// Collect linked peers before deletion (for cascade and response).
	// cascade_only=ID,ID limits the cascade to the linked peers it names:
	// the console checks an account's scope on the linked peers it read,
	// and a peer linked after that read is not deleted with this one.
	var cascadeOnly map[string]bool
	if r.URL.Query().Has("cascade_only") {
		cascadeOnly = map[string]bool{}
		for _, lid := range strings.Split(r.URL.Query().Get("cascade_only"), ",") {
			cascadeOnly[lid] = true
		}
	}
	var linkedIDs []string
	if revoke || cascade {
		if linked, err := s.db.GetLinkedPeers(id); err == nil {
			for _, lp := range linked {
				if cascadeOnly == nil || cascadeOnly[lp.ID] {
					linkedIDs = append(linkedIDs, lp.ID)
				}
			}
		}
	}

	// Revocation: the device ID goes on the blocklist first, which keeps it
	// in the database, so the ban survives a restart also after a hard
	// delete. A ban that cannot be stored leaves the device as it is.
	if revoke && s.blocklist != nil {
		if err := s.blocklist.BlockID(id, "revoked via panel"); err != nil {
			writeInternalError(w, err, "RevokePeer")
			return
		}
	}

	var err error
	if hard {
		err = s.db.HardDeletePeer(id)
	} else {
		err = s.db.DeletePeer(id)
	}
	if err != nil {
		writeInternalError(w, err, "DeletePeer")
		return
	}
	if hard {
		s.forgetSecureDeviceState(id)
	}
	if revoke && !hard {
		if err := s.db.BanPeer(id, "revoked via panel"); err != nil {
			writeInternalError(w, err, "RevokePeer")
			return
		}
	}

	// Remove from memory (closes TCP/WS connections — Phase 3.9).
	s.peers.Remove(id)

	// CDAP revocation: send revoke message and disconnect CDAP device.
	if revoke && s.cdapGw != nil {
		if err := s.cdapGw.SendRevoke(r.Context(), id, "revoked via panel"); err != nil {
			// Not an error — device may not be CDAP-connected
			_ = err
		}
	}

	// Cascade: revoke linked devices (e.g., paired mobile→desktop).
	var cascadedIDs []string
	if cascade && len(linkedIDs) > 0 {
		for _, lid := range linkedIDs {
			if hard {
				if err := s.db.HardDeletePeer(lid); err == nil {
					s.forgetSecureDeviceState(lid)
				}
			} else {
				s.db.DeletePeer(lid)
				if revoke {
					s.db.BanPeer(lid, "revoked via cascade")
				}
			}
			s.peers.Remove(lid)
			if revoke && s.blocklist != nil {
				if err := s.blocklist.BlockID(lid, "revoked via cascade"); err != nil {
					log.Printf("[API] RevokePeer: the ban of linked device %s was not stored: %v", lid, err)
				}
			}
			if revoke && s.cdapGw != nil {
				s.cdapGw.SendRevoke(r.Context(), lid, "revoked via cascade")
			}
			cascadedIDs = append(cascadedIDs, lid)
		}
	}

	// Publish event.
	if s.eventBus != nil {
		action := eventsModule.EventPeerDeleted
		if revoke {
			action = eventsModule.EventPeerRevoked
		}
		s.eventBus.Publish(eventsModule.Event{
			Type: action,
			Data: map[string]string{
				"id":      id,
				"hard":    fmt.Sprintf("%v", hard),
				"revoke":  fmt.Sprintf("%v", revoke),
				"cascade": fmt.Sprintf("%v", cascadedIDs),
			},
		})
	}

	// Audit log.
	if s.auditLog != nil {
		action := audit.ActionPeerDeleted
		if revoke {
			action = audit.ActionPeerRevoked
		}
		details := map[string]string{
			"hard":    fmt.Sprintf("%v", hard),
			"revoke":  fmt.Sprintf("%v", revoke),
			"cascade": fmt.Sprintf("%v", cascade),
		}
		if len(cascadedIDs) > 0 {
			details["cascaded_ids"] = fmt.Sprintf("%v", cascadedIDs)
		}
		s.auditLog.Log(action, s.eventActor(r), id, details)
	}

	resp := map[string]interface{}{
		"status":  "deleted",
		"id":      id,
		"revoked": revoke,
	}
	if len(cascadedIDs) > 0 {
		resp["cascaded"] = cascadedIDs
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBanPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.deviceInScope(w, r, id) {
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	if err := s.db.BanPeer(id, body.Reason); err != nil {
		writeInternalError(w, err, "BanPeer")
		return
	}
	s.credentialsEnded(id)

	// Remove peer from in-memory map to force immediate disconnect.
	// The peer will be rejected on next RegisterPeer/RegisterPk attempt.
	wasConnected := s.peers.Get(id) != nil
	s.peers.Remove(id)

	// A connected peer goes offline now (and was last seen now). A peer that
	// wasn't connected keeps its last-seen time and address.
	if wasConnected {
		s.db.UpdatePeerStatus(id, "OFFLINE", "", "admin")
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerBanned, s.eventActor(r), id, map[string]string{"reason": body.Reason})
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "banned", "id": id})
}

func (s *Server) handleUnbanPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.deviceInScope(w, r, id) {
		return
	}

	peerRow, _ := s.db.GetPeer(id)
	rejected, _ := s.db.GetConfig(rejectedDevicePrefix + id)
	decision, _ := s.db.GetConfig(enrollmentDecisionPrefix + id)
	enrollmentRejectBan := peerRow != nil && peerRow.BanReason == enrollmentRejectBanReason &&
		enrollmentRejectAuditPeer(peerRow, rejected, decision)

	// Enrollment Reject & Ban created an audit-only peer. Unban must remove it
	// so managed mode re-queues for approval instead of treating the ID as enrolled.
	if enrollmentRejectBan {
		s.clearEnrollmentRejectionState(id)
		if err := s.removeEnrollmentRejectAuditPeer(id); err != nil {
			writeInternalError(w, err, "removeEnrollmentRejectAuditPeer")
			return
		}
		if s.auditLog != nil {
			s.auditLog.Log(audit.ActionPeerUnbanned, s.eventActor(r), id, map[string]string{
				"peer_removed": "true",
				"reason":       enrollmentRejectBanReason,
			})
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "id": id, "peer_removed": "true"})
		return
	}

	if err := s.db.UnbanPeer(id); err != nil {
		writeInternalError(w, err, "UnbanPeer")
		return
	}

	s.peers.SetBanned(id, false)

	// Also clear enrollment rejection lock so the device can re-queue.
	s.clearEnrollmentRejectionState(id)

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerUnbanned, s.eventActor(r), id, nil)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "id": id})
}

// handleRestorePeer clears the soft_deleted flag on a previously deleted peer.
// SECURITY (GHSA-3v82-3gf8-fxx8): This is the ONLY supported path for bringing
// a deleted device back. UpsertPeer no longer restores rows implicitly.
func (s *Server) handleRestorePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.deviceInScope(w, r, id) {
		return
	}

	deleted, err := s.db.IsPeerSoftDeleted(id)
	if err != nil {
		writeInternalError(w, err, "IsPeerSoftDeleted")
		return
	}
	if !deleted {
		live, gerr := s.db.GetPeer(id)
		if gerr != nil {
			writeInternalError(w, gerr, "GetPeer")
			return
		}
		if live == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_active", "id": id})
		return
	}

	if err := s.db.RestorePeer(id); err != nil {
		writeInternalError(w, err, "RestorePeer")
		return
	}

	if err := s.db.UnbanPeer(id); err != nil {
		log.Printf("[api] handleRestorePeer: UnbanPeer failed for %s: %v", id, err)
	}
	if s.blocklist != nil {
		s.blocklist.UnblockID(id)
	}

	if s.eventBus != nil {
		s.eventBus.Publish(eventsModule.Event{
			Type: eventsModule.EventPeerRestored,
			Data: map[string]string{"id": id},
		})
	}
	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerRestored, s.eventActor(r), id, nil)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "restored", "id": id})
}

func (s *Server) handleChangePeerID(w http.ResponseWriter, r *http.Request) {
	oldID := r.PathValue("id")
	if !s.deviceInScope(w, r, oldID) {
		return
	}

	var body struct {
		NewID string `json:"new_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.NewID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_id is required"})
		return
	}

	// Validate new peer ID format (H1: prevent injection of arbitrary IDs)
	if !peerIDRegexp.MatchString(body.NewID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid peer ID format. Must be 6-16 alphanumeric characters, hyphens, or underscores.",
		})
		return
	}

	targetState, err := s.db.GetPeerIDState(body.NewID)
	if err != nil {
		writeInternalError(w, err, "GetPeerIDState")
		return
	}
	switch targetState {
	case db.PeerIDActive:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Device ID already exists"})
		return
	case db.PeerIDSoftDeleted:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "This ID belongs to a deleted device. Restore or permanently delete that device before reusing the ID."})
		return
	}

	if err := s.db.ChangePeerID(oldID, body.NewID, "panel"); err != nil {
		if errors.Is(err, db.ErrPeerIDExists) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "Device ID already exists"})
			return
		}
		if errors.Is(err, db.ErrPeerIDSoftDeleted) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "This ID belongs to a deleted device. Restore or permanently delete that device before reusing the ID."})
			return
		}
		if errors.Is(err, db.ErrPeerNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
		// Log the actual error but return a generic message to prevent leakage
		log.Printf("[API] ChangePeerID %s -> %s: %v", oldID, body.NewID, err)
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Failed to change peer ID (ID conflict or not found)"})
		return
	}

	// Preserve a live TCP/WSS registration while changing its map key.
	s.peers.Rename(oldID, body.NewID)

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerIDChanged, s.eventActor(r), oldID, map[string]string{"new_id": body.NewID})
	}

	if s.eventBus != nil {
		s.eventBus.Publish(eventsModule.Event{
			Type: eventsModule.EventPeerIDChanged,
			Data: map[string]string{
				"old_id": oldID,
				"new_id": body.NewID,
				"source": "panel",
			},
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "changed",
		"old_id": oldID,
		"new_id": body.NewID,
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	// M6: Validate config key name to prevent arbitrary key injection
	if !configKeyRegexp.MatchString(key) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid config key. Must be 1-64 alphanumeric characters, underscores, hyphens, or dots.",
		})
		return
	}
	if configKeyIsSecret(key) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "This key holds a secret and is not served here"})
		return
	}

	val, err := s.db.GetConfig(key)
	if err != nil {
		writeInternalError(w, err, "GetConfig")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": key, "value": val})
}

func (s *Server) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	// M6: Validate config key name to prevent arbitrary key injection
	if !configKeyRegexp.MatchString(key) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid config key. Must be 1-64 alphanumeric characters, underscores, hyphens, or dots.",
		})
		return
	}
	if configKeyIsSecret(key) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "This key holds a secret and is not served here"})
		return
	}

	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}
	if err := s.db.SetConfig(key, body.Value); err != nil {
		writeInternalError(w, err, "SetConfig")
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionConfigChanged, s.eventActor(r), key, nil)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "key": key})
}

// --- New Phase 4 Handlers ---

// handleStatusSummary returns aggregate device status counts.
// GET /api/peers/status/summary
func (s *Server) handleStatusSummary(w http.ResponseWriter, r *http.Request) {
	stats := s.peers.GetStats(config.DegradedThreshold, config.CriticalThreshold)
	writeJSON(w, http.StatusOK, stats)
}

// handleOnlinePeers returns detailed snapshots of all currently online peers.
// GET /api/peers/online
func (s *Server) handleOnlinePeers(w http.ResponseWriter, r *http.Request) {
	snapshots := s.peers.GetAllSnapshots(config.DegradedThreshold, config.CriticalThreshold)
	visible, err := s.visibleSnapshotIDs(r, snapshots)
	if err != nil {
		writeInternalError(w, err, "device scope")
		return
	}
	if visible != nil {
		kept := make([]peer.Snapshot, 0, len(snapshots))
		for _, snap := range snapshots {
			if visible[snap.ID] {
				kept = append(kept, snap)
			}
		}
		snapshots = kept
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(snapshots),
		"peers": snapshots,
	})
}

// handlePeerStatus returns detailed live status for a specific peer.
// GET /api/peers/{id}/status
func (s *Server) handlePeerStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	snap, ok := s.peers.GetSnapshot(id, config.DegradedThreshold, config.CriticalThreshold)
	if !ok {
		// Not in memory — check database for historical data
		dbPeer, err := s.db.GetPeer(id)
		if err != nil {
			writeInternalError(w, err, "GetPeer (status)")
			return
		}
		if dbPeer == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Peer not found"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":          id,
			"status":      peer.StatusOffline,
			"in_memory":   false,
			"db_status":   dbPeer.Status,
			"last_online": dbPeer.LastOnline,
			"hostname":    dbPeer.Hostname,
			"os":          dbPeer.OS,
			"version":     dbPeer.Version,
		})
		return
	}

	// Peer is in memory — return full live snapshot
	writeJSON(w, http.StatusOK, map[string]any{
		"in_memory": true,
		"snapshot":  snap,
	})
}

// handlePeerAvailability returns server-observed status transitions for one local day.
// GET /api/peers/{id}/availability?day=YYYY-MM-DD&tz_offset=<js getTimezoneOffset()>
func (s *Server) handlePeerAvailability(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || !peerIDRegexp.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid peer ID"})
		return
	}
	if !s.deviceInScope(w, r, id) {
		return
	}

	enabled := s.db.IsAvailabilityHistoryEnabled()
	retention := s.db.AvailabilityHistoryRetentionDays()
	day := r.URL.Query().Get("day")
	if day == "" {
		day = time.Now().UTC().Format("2006-01-02")
	}
	tzOffset := 0
	if raw := r.URL.Query().Get("tz_offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			tzOffset = parsed
		}
	}

	from, to, err := db.LocalDayBounds(day, tzOffset)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid day; expected YYYY-MM-DD"})
		return
	}

	events := []*db.PeerAvailabilityEvent{}
	if enabled {
		events, err = s.db.GetPeerAvailabilityEvents(id, from, to)
		if err != nil {
			writeInternalError(w, err, "GetPeerAvailabilityEvents")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id":        id,
		"enabled":        enabled,
		"retention_days": retention,
		"day":            day,
		"tz_offset":      tzOffset,
		"from":           from.UTC().Format(time.RFC3339),
		"to":             to.UTC().Format(time.RFC3339),
		"count":          len(events),
		"events":         events,
	})
}

// handlePeerConnectionSessions returns server-observed remote-control sessions.
// GET /api/peers/{id}/connection-sessions?limit=50
func (s *Server) handlePeerConnectionSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || !peerIDRegexp.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid peer ID"})
		return
	}
	if !s.deviceInScope(w, r, id) {
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	sessions, err := s.db.ListPeerConnectionSessions(id, limit)
	if err != nil {
		writeInternalError(w, err, "ListPeerConnectionSessions")
		return
	}
	if sessions == nil {
		sessions = []*db.PeerConnectionSession{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id":  id,
		"count":    len(sessions),
		"sessions": sessions,
	})
}

// handlePeerMetrics returns historical metrics (CPU, memory, disk) for a peer.
// GET /api/peers/{id}/metrics?limit=100
func (s *Server) handlePeerMetrics(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || !peerIDRegexp.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid peer ID"})
		return
	}
	if !s.deviceInScope(w, r, id) {
		return
	}

	// Parse optional limit param (default 100, max 1000)
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	metrics, err := s.db.GetPeerMetrics(id, limit)
	if err != nil {
		writeInternalError(w, err, "GetPeerMetrics")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id": id,
		"count":   len(metrics),
		"metrics": metrics,
	})
}

// handleListBlocklist returns all blocklist entries.
// GET /api/blocklist
func (s *Server) handleListBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.blocklist == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"entries": []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"count":   s.blocklist.Count(),
		"entries": s.blocklist.List(),
	})
}

// handleAddBlocklist adds an entry to the blocklist.
// POST /api/blocklist
func (s *Server) handleAddBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.blocklist == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Blocklist not enabled",
		})
		return
	}

	var body struct {
		Value  string `json:"value"`
		Type   string `json:"type"` // "ip", "id", or "cidr"
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "value is required"})
		return
	}

	switch body.Type {
	case "ip":
		if err := s.blocklist.BlockIP(body.Value, body.Reason); err != nil {
			writeInternalError(w, err, "BlockIP")
			return
		}
	case "id":
		if err := s.blocklist.BlockID(body.Value, body.Reason); err != nil {
			writeInternalError(w, err, "BlockID")
			return
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(body.Value); err != nil {
			log.Printf("[API] Invalid CIDR %s: %v", body.Value, err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid CIDR notation"})
			return
		}
		if err := s.blocklist.BlockCIDR(body.Value, body.Reason); err != nil {
			writeInternalError(w, err, "BlockCIDR")
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be ip, id, or cidr"})
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionBlocklistAdd, s.eventActor(r), body.Value, map[string]string{
			"type": body.Type, "reason": body.Reason,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "blocked", "value": body.Value})
}

// handleRemoveBlocklist removes an entry from the blocklist.
// DELETE /api/blocklist/{entry}
func (s *Server) handleRemoveBlocklist(w http.ResponseWriter, r *http.Request) {
	entry := r.PathValue("entry")
	if s.blocklist == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Blocklist not enabled",
		})
		return
	}

	removed := s.blocklist.UnblockIP(entry) || s.blocklist.UnblockID(entry) || s.blocklist.UnblockCIDR(entry)
	if !removed {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Entry not found"})
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionBlocklistRemove, s.eventActor(r), entry, nil)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked", "entry": entry})
}

// --- Helpers ---

var startTime = time.Now()

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeInternalError logs the actual error internally and returns a generic
// "Internal server error" message to the client. This prevents leaking
// sensitive implementation details (file paths, SQL queries, stack traces).
func writeInternalError(w http.ResponseWriter, err error, action string) {
	log.Printf("[API] %s failed: %v", action, err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
}

// forwardedHeader is the value of a reverse proxy's X-Forwarded-* header,
// "" unless the request comes from a trusted proxy (TRUST_PROXY and
// TRUSTED_PROXIES): any client can send the header itself.
func (s *Server) forwardedHeader(r *http.Request, name string) string {
	if s.cfg == nil || !s.cfg.ShouldHonorForwardedHeaders(r.RemoteAddr) {
		return ""
	}
	return r.Header.Get(name)
}

// remoteIP is the client's address (config's ClientIP): behind a trusted
// proxy (TRUST_PROXY and TRUSTED_PROXIES) the rightmost X-Forwarded-For
// entry that is not a trusted proxy, else X-Real-IP; the socket's address
// otherwise, and when neither header holds an address.
func (s *Server) remoteIP(r *http.Request) string {
	return s.cfg.ClientIP(r)
}

// eventActor names who acted, for a server event: the account the console
// acts for on an in-process call, else the caller's account or API key
// (actorFromCtx), else the client's address, where no account acted (a
// sign-in, a device).
func (s *Server) eventActor(r *http.Request) string {
	if actor := actorFromCtx(r); actor != "" {
		return actor
	}
	return s.remoteIP(r)
}

// --- Tags Handlers ---

// handleSetPeerTags updates tags for a peer.
// PUT /api/peers/{id}/tags
// Accepts either { "tags": "tag1,tag2" } (string) or { "tags": ["tag1","tag2"] } (array).
func (s *Server) handleSetPeerTags(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var raw json.RawMessage
	var wrapper struct {
		Tags json.RawMessage `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}
	raw = wrapper.Tags

	// Determine if tags is a string or an array
	var tagsStr string
	if len(raw) > 0 && raw[0] == '"' {
		// JSON string
		if err := json.Unmarshal(raw, &tagsStr); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid tags value"})
			return
		}
	} else if len(raw) > 0 && raw[0] == '[' {
		// JSON array
		var arr []string
		if err := json.Unmarshal(raw, &arr); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid tags array"})
			return
		}
		tagsStr = strings.Join(arr, ",")
	} else if len(raw) == 0 || string(raw) == "null" {
		tagsStr = ""
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Tags must be a string or array"})
		return
	}

	if err := s.db.UpdatePeerTags(id, tagsStr); err != nil {
		writeInternalError(w, err, "UpdatePeerTags")
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerTagsUpdated, s.eventActor(r), id, map[string]string{"tags": tagsStr})
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "id": id, "tags": tagsStr})
}

// tagsText is a tags value as a peer stores it: a text as it is, a list of
// texts joined with commas. ok is false for any other value.
func tagsText(raw json.RawMessage) (string, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, true
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, ","), true
	}
	return "", false
}

// handlePeersByTag returns peers matching a tag.
// GET /api/peers/by-tag/{tag}
func (s *Server) handlePeersByTag(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	peers, err := s.db.ListPeersByTag(tag)
	if err != nil {
		writeInternalError(w, err, "ListPeersByTag")
		return
	}
	if peers, err = s.visiblePeers(r, peers); err != nil {
		writeInternalError(w, err, "device scope")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tag":   tag,
		"count": len(peers),
		"peers": peers,
	})
}

// --- Audit Handler ---

// handleAuditEvents returns the server events newest first, those of one
// action when it is given, from offset on, and how many there are of them
// (total): the events kept in the database for audit.RetentionDays.
// GET /api/audit/events?limit=50&offset=0&action=peer_banned
func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if s.auditLog == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"events":  []any{},
		})
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &limit); err != nil || n != 1 {
			limit = 50
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &offset); err != nil || n != 1 || offset < 0 {
			offset = 0
		}
	}

	action := r.URL.Query().Get("action")
	events, total, err := s.auditLog.Page(audit.Action(action), limit, offset)
	if err != nil {
		writeInternalError(w, err, "audit events")
		return
	}
	if events == nil && action != "" {
		events = []audit.Event{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"total":   total,
		"count":   len(events),
		"events":  events,
	})
}

// --- Metrics Handler ---

// handleMetrics serves Prometheus text exposition format metrics.
// GET /metrics
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		http.Error(w, "metrics not available", http.StatusServiceUnavailable)
		return
	}

	// Refresh gauge values from current state
	if s.peers != nil {
		peerStats := s.peers.GetStats(config.DegradedThreshold, config.CriticalThreshold)
		snap := s.peers.GetAllSnapshots(
			config.DegradedThreshold,
			config.CriticalThreshold,
		)
		var online, degraded, critical, offline int64
		for _, p := range snap {
			switch p.Status {
			case peer.StatusOnline:
				online++
			case peer.StatusDegraded:
				degraded++
			case peer.StatusCritical:
				critical++
			default:
				offline++
			}
		}
		s.metrics.PeersTotal.Store(int64(len(snap)))
		s.metrics.PeersOnline.Store(online)
		s.metrics.PeersDegraded.Store(degraded)
		s.metrics.PeersCritical.Store(critical)
		s.metrics.PeersOffline.Store(offline)
		s.metrics.PeersUDP.Store(int64(peerStats.UDP))
		s.metrics.PeersTCP.Store(int64(peerStats.TCP))
		s.metrics.PeersWS.Store(int64(peerStats.WS))
		banned := int64(peerStats.Banned)
		if n, err := s.db.GetBannedPeerCount(); err == nil {
			banned = int64(n)
		}
		s.metrics.PeersBanned.Store(banned)
		s.metrics.TotalRegistrations.Store(s.peers.TotalRegistrations())
		s.metrics.TotalExpired.Store(s.peers.TotalExpired())
	}

	if s.bwLimiter != nil {
		s.metrics.ThrottleHits.Store(s.bwLimiter.Stats().ThrottleHits)
	}

	if s.auditLog != nil {
		s.metrics.AuditEvents.Store(s.auditLog.Logged())
	}

	if s.relay != nil {
		s.metrics.RelayActiveSessions.Store(s.relay.ActiveSessions.Load())
		s.metrics.TotalRelaySessions.Store(s.relay.TotalRelayed.Load())
	}

	if s.billing != nil {
		s.metrics.BillingPendingRelays.Store(int64(s.billing.PendingRelayCount()))
	}

	if s.blocklist != nil {
		s.metrics.BlocklistCount.Store(int64(s.blocklist.Count()))
	}

	if s.eventBus != nil {
		s.metrics.EventSubscribers.Store(int64(s.eventBus.Count()))
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.WritePrometheus(w)
}

// --- WebSocket Events Handler ---

// handleWSEvents upgrades the HTTP connection to WebSocket and streams events.
// GET /api/ws/events?filter=peer_online
func (s *Server) handleWSEvents(w http.ResponseWriter, r *http.Request) {
	if s.eventBus == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Event bus not available",
		})
		return
	}

	acceptOpts := &websocket.AcceptOptions{}
	if origins := s.cfg.GetAPIAllowedWSOrigins(); len(origins) > 0 {
		acceptOpts.OriginPatterns = origins
	}

	conn, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		log.Printf("[api] WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.CloseNow()

	filter := eventsModule.EventType(r.URL.Query().Get("filter"))
	sub := s.eventBus.Subscribe(filter)
	defer s.eventBus.Unsubscribe(sub)

	ctx := r.Context()
	log.Printf("[api] WebSocket events client connected (filter=%q)", filter)

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "server closing")
			return
		case evt, ok := <-sub.Ch:
			if !ok {
				conn.Close(websocket.StatusNormalClosure, "unsubscribed")
				return
			}
			data := eventsModule.MarshalEvent(evt)
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				log.Printf("[api] WebSocket write error: %v", err)
				return
			}
		}
	}
}

// POST /api/peers/{id}/wol — Send Wake-on-LAN magic packet (Phase 44)
func (s *Server) handleWakeOnLan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, `{"error":"missing peer id"}`, http.StatusBadRequest)
		return
	}

	peer, err := s.db.GetPeer(id)
	if err != nil || peer == nil {
		http.Error(w, `{"error":"peer not found"}`, http.StatusNotFound)
		return
	}

	// Try to get MAC from request body (operator may provide it)
	var body struct {
		MAC string `json:"mac"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	mac := body.MAC
	if mac == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "MAC address required. Provide {\"mac\": \"AA:BB:CC:DD:EE:FF\"} in request body.",
		})
		return
	}

	if err := sendWOLPacket(mac); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   fmt.Sprintf("Failed to send WOL packet: %v", err),
		})
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerUpdated, s.eventActor(r), id, map[string]string{"action": "wol", "mac": mac})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mac": mac})
}

// sendWOLPacket sends a Wake-on-LAN magic packet to the given MAC address.
func sendWOLPacket(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", macStr, err)
	}

	// Build magic packet: 6 bytes of 0xFF + 16 repetitions of MAC address
	var packet [102]byte
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], mac)
	}

	// Send via UDP broadcast
	addr, err := net.ResolveUDPAddr("udp4", "255.255.255.255:9")
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(packet[:])
	return err
}

// ============================================================
// Access Policy Handlers (Unattended Access Management)
// ============================================================

func (s *Server) handleGetAccessPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "peer ID required"})
		return
	}

	// The device's organization, "" for none: the console reads the
	// organization's connection mode and operators from it to say what
	// the receiver does
	orgID, _ := s.db.GetDeviceOrgID(id)
	policy, err := s.db.GetAccessPolicy(id)
	if err != nil {
		// No policy = defaults (all disabled)
		writeJSON(w, http.StatusOK, map[string]any{
			"peer_id":             id,
			"org_id":              orgID,
			"unattended_enabled":  false,
			"password_set":        false,
			"schedule_enabled":    false,
			"schedule_days":       "",
			"schedule_start_time": "",
			"schedule_end_time":   "",
			"schedule_timezone":   "",
			"allowed_operators":   "",
			"updated_at":          "",
			"updated_by":          "",
		})
		return
	}

	writeJSON(w, http.StatusOK, struct {
		*db.AccessPolicy
		OrgID string `json:"org_id"`
	}{policy, orgID})
}

func (s *Server) handleSaveAccessPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "peer ID required"})
		return
	}

	var body struct {
		UnattendedEnabled bool   `json:"unattended_enabled"`
		Password          string `json:"password,omitempty"`       // Plain text — will be hashed
		ClearPassword     bool   `json:"clear_password,omitempty"` // If true, remove password
		ScheduleEnabled   bool   `json:"schedule_enabled"`
		ScheduleDays      string `json:"schedule_days"`
		ScheduleStartTime string `json:"schedule_start_time"`
		ScheduleEndTime   string `json:"schedule_end_time"`
		ScheduleTimezone  string `json:"schedule_timezone"`
		AllowedOperators  string `json:"allowed_operators"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}

	// Validate schedule time format (HH:MM)
	timeRe := regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	if body.ScheduleEnabled {
		if body.ScheduleStartTime != "" && !timeRe.MatchString(body.ScheduleStartTime) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid schedule_start_time format (HH:MM)"})
			return
		}
		if body.ScheduleEndTime != "" && !timeRe.MatchString(body.ScheduleEndTime) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid schedule_end_time format (HH:MM)"})
			return
		}
	}

	// The schedule counts in an IANA time zone the caller check knows: a
	// zone it does not know would refuse every unattended connection
	if tz := strings.TrimSpace(body.ScheduleTimezone); tz != "" && unattended.Zone(tz) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown schedule_timezone: " + tz})
		return
	}

	// Validate schedule days
	validDays := map[string]bool{"mon": true, "tue": true, "wed": true, "thu": true, "fri": true, "sat": true, "sun": true}
	if body.ScheduleDays != "" {
		for _, d := range strings.Split(body.ScheduleDays, ",") {
			if !validDays[strings.TrimSpace(strings.ToLower(d))] {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid day in schedule_days: " + d})
				return
			}
		}
	}

	policy := &db.AccessPolicy{
		PeerID:            id,
		UnattendedEnabled: body.UnattendedEnabled,
		ScheduleEnabled:   body.ScheduleEnabled,
		ScheduleDays:      body.ScheduleDays,
		ScheduleStartTime: body.ScheduleStartTime,
		ScheduleEndTime:   body.ScheduleEndTime,
		ScheduleTimezone:  strings.TrimSpace(body.ScheduleTimezone),
		AllowedOperators:  body.AllowedOperators,
		// Who changed it: the signed-in account (the console's account
		// for a call through the console), and when
		UpdatedBy: actorFromCtx(r),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Hash password if provided
	if body.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to hash password"})
			return
		}
		policy.PasswordHash = string(hash)
	} else if body.ClearPassword {
		policy.PasswordHash = "CLEAR"
	}
	// If PasswordHash is empty string, SaveAccessPolicy preserves existing hash

	if err := s.db.SaveAccessPolicy(policy); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to save access policy"})
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerUpdated, s.eventActor(r), id, map[string]string{
			"action":     "access_policy_updated",
			"unattended": fmt.Sprintf("%v", body.UnattendedEnabled),
			"schedule":   fmt.Sprintf("%v", body.ScheduleEnabled),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleDeleteAccessPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "peer ID required"})
		return
	}

	if err := s.db.DeleteAccessPolicy(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to delete access policy"})
		return
	}

	if s.auditLog != nil {
		s.auditLog.Log(audit.ActionPeerUpdated, s.eventActor(r), id, map[string]string{
			"action": "access_policy_deleted",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

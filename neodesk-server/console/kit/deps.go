package kit

import (
	"context"
	"net/http"

	"github.com/neodeskapp/neodesk/neodesk-server/console/access"
	"github.com/neodeskapp/neodesk/neodesk-server/console/admintoken"
	"github.com/neodeskapp/neodesk/neodesk-server/console/alerts"
	"github.com/neodeskapp/neodesk/neodesk-server/console/auditlog"
	"github.com/neodeskapp/neodesk/neodesk-server/console/authn"
	"github.com/neodeskapp/neodesk/neodesk-server/console/avatars"
	"github.com/neodeskapp/neodesk/neodesk-server/console/branding"
	"github.com/neodeskapp/neodesk/neodesk-server/console/chatstore"
	"github.com/neodeskapp/neodesk/neodesk-server/console/config"
	"github.com/neodeskapp/neodesk/neodesk-server/console/csrf"
	"github.com/neodeskapp/neodesk/neodesk-server/console/devicegroups"
	"github.com/neodeskapp/neodesk/neodesk-server/console/filetransfer"
	"github.com/neodeskapp/neodesk/neodesk-server/console/generator"
	"github.com/neodeskapp/neodesk/neodesk-server/console/goapi"
	"github.com/neodeskapp/neodesk/neodesk-server/console/guestaccess"
	"github.com/neodeskapp/neodesk/neodesk-server/console/i18n"
	"github.com/neodeskapp/neodesk/neodesk-server/console/limits"
	"github.com/neodeskapp/neodesk/neodesk-server/console/mail"
	"github.com/neodeskapp/neodesk/neodesk-server/console/ndrelay"
	"github.com/neodeskapp/neodesk/neodesk-server/console/onboard"
	"github.com/neodeskapp/neodesk/neodesk-server/console/remoterelay"
	"github.com/neodeskapp/neodesk/neodesk-server/console/restart"
	"github.com/neodeskapp/neodesk/neodesk-server/console/serverinfo"
	"github.com/neodeskapp/neodesk/neodesk-server/console/servermgmt"
	"github.com/neodeskapp/neodesk/neodesk-server/console/session"
	"github.com/neodeskapp/neodesk/neodesk-server/console/setupguide"
	"github.com/neodeskapp/neodesk/neodesk-server/console/statuspush"
	"github.com/neodeskapp/neodesk/neodesk-server/console/store"
	"github.com/neodeskapp/neodesk/neodesk-server/console/updater"
	"github.com/neodeskapp/neodesk/neodesk-server/console/webui"
	"github.com/neodeskapp/neodesk/neodesk-server/console/ws"
)

// Jobs is where a group adds background work that runs for as long as
// the console does (package console/jobs). run must return when its
// context ends.
type Jobs interface {
	Add(name string, run func(ctx context.Context))
}

// Deps is what a route group gets in Register: the two route tables, the
// console's services, and the guards as methods (see guards.go).
type Deps struct {
	// Router is the table of the console's routes (step 18 of the
	// pipeline): behind the session, the panel access guard, the rate
	// limiters, the request language, the CSRF gate and the JSON
	// content-type rule.
	Router *Router
	// Early is the table of the RustDesk client API and the device API
	// under /api/nd (steps 12 and 13): behind the session, the guard and
	// the limiters, but before the request language and the CSRF gate. Its
	// answers are never compressed. A handler there that calls PassOn
	// leaves the request to Router.
	Early *Router

	// Config is the console's configuration.
	Config *config.Config
	// Store is the console's database.
	Store *store.DB
	// Chat is the chat's conversations, read marks, edits, reactions and
	// canned replies, on Store (A242).
	Chat *chatstore.Store
	// Sessions is the session manager (sign-in, sign-out, session list).
	Sessions *session.Manager
	// Authn is the sign-in service: passwords, the second factor, lockouts,
	// access tokens and device tokens (services/authService.js).
	Authn *authn.Service
	// CSRF hands out and checks CSRF tokens. The pipeline already checks
	// every write that reaches Router.
	CSRF *csrf.Protector
	// Access decides permissions, panel access and device scope.
	Access *access.Service
	// Limits holds the rate limiters: d.Limits.Upload.Middleware goes on
	// a route like uploadLimiter did.
	Limits *limits.Set
	// I18n holds the languages (I18n.Bundle) and the language routes.
	I18n *i18n.Handlers
	// WebUI serves the web app and its error pages.
	WebUI *webui.Host
	// GoAPI is the client for the API server in this process
	// (services/neodeskApi.js).
	GoAPI *goapi.Client
	// ServerInfo answers how clients reach this server: the keys, the
	// addresses, the client configuration (services/keyService.js,
	// services/clientConfigHost.js and the services next to them).
	ServerInfo *serverinfo.Service
	// Avatars keeps the profile pictures of console users
	// (services/avatarService.js, lib/avatarImage.js).
	Avatars *avatars.Service
	// GuestAccess reads and checks the tokens of guest access links
	// (middleware/guestAccess.js).
	GuestAccess *guestaccess.Service
	// FileTransfer keeps the file transfers between the console and
	// devices (services/fileTransferService.js).
	FileTransfer *filetransfer.Service
	// Restart collects the saved settings that need a restart of the
	// server and runs that restart (services/restartCoordinator.js).
	Restart *restart.Service
	// DeviceGroups holds folders, device groups and user groups and
	// answers which devices an account may see (services/deviceGroupService.js
	// with its dbAdapter methods).
	DeviceGroups *devicegroups.Service
	// Backend is the device layer: the API server's devices with what the
	// console's tables add to them (services/serverBackend.js).
	Backend *goapi.Backend
	// Branding is the console's own look: the appearance settings, the
	// stylesheet made from them, profiles, themes and fonts
	// (services/brandingService.js, fontService.js). Its cache is what
	// every route reads; the writes reload it.
	Branding *branding.Service
	// Mail is the mail service: the SMTP settings, the alert and help
	// request mails, the log of notifications sent
	// (services/emailService.js, lib/smtpSettingsHandlers.js).
	Mail *mail.Service
	// Alerts is the alert rules engine (services/alertRulesEngine.js).
	Alerts *alerts.Engine
	// Generator is the support client generator: bundles, the template
	// module, the client builder and the build queue
	// (services/agentBundleService.js, supportGeneratorModule.js,
	// clientBuilderService.js, clientTemplateWorker.js).
	Generator *generator.Service
	// Updater installs release binaries, keeps the update backups and
	// reports what the install can do (services/updateService.js,
	// lib/managementCapabilities.js).
	Updater *updater.Service
	// Audit writes the audit log. LogAction is the usual way to it.
	Audit *auditlog.Log
	// Unattended holds the unattended sessions the server vouched for
	// until the relay ends them (Server.RelayEnded writes their end).
	Unattended *onboard.UnattendedBook
	// Log is the console's logger; a group takes d.Log.Child("TICKETS").
	Log *Logger
	// Jobs takes background work that stops with the console.
	Jobs Jobs
	// Leases says which of the once-per-installation jobs this instance
	// runs (leases.go); a job asks d.Held before each run. nil runs them
	// all, as a lone console does.
	Leases Leases
	// Clustered is set when the console shares its installation with
	// other instances (VALKEY_URL).
	Clustered bool
	// Sockets is the registry of the console's websockets: a service adds
	// a socket path with d.Sockets.Handle (package console/ws). An upgrade
	// to a path nobody registered passes the request pipeline like a plain
	// request and ends in its 404.
	Sockets *ws.Registry
	// StatusPush pushes device status and panel events to the browsers
	// (services/deviceStatusPush.js); d.StatusPush.PublishPanelEvent is
	// publishPanelEvent.
	StatusPush *statuspush.Service
	// Relay is the agents' signal and relay sockets (services/bdRelay.js);
	// d.Relay.RequestFromDevice asks a connected agent for something.
	Relay *ndrelay.Service
	// RemoteRelay is the remote desktop relay between agents and viewers
	// (services/remoteRelay.js): its sessions and the agents' single-use
	// tokens.
	RemoteRelay *remoterelay.Service
	// ServerMgmt is the server management: the machine's resources (also
	// read by the server attestation), the file browser and the system
	// services (services/serverManagement.js).
	ServerMgmt *servermgmt.Service
	// AdminTokens keeps the API tokens for scripts and the command line;
	// admintoken.FromRequest(r) is the token a request came with.
	AdminTokens *admintoken.Service
	// SetupGuide is the first-install guide on the overview: who sees it
	// and which of its steps the server sees done.
	SetupGuide *setupguide.Service
}

// At returns the same Deps with both route tables mounted at prefix, for
// a group that the old console mounted there:
//
//	inventory.Register(d.At("/api/inventory"))
//	inventory.Register(d.At("/api/nd"))
//
// The group writes its patterns below the mount ("/", "/{id}").
func (d *Deps) At(prefix string) *Deps {
	mounted := *d
	if d.Router != nil {
		mounted.Router = d.Router.Mount(prefix)
	}
	if d.Early != nil {
		mounted.Early = d.Early.Mount(prefix)
	}
	return &mounted
}

// LogAction writes an audit log entry for the signed-in account and the
// client's address: db.logAction(req.session.userId, action, details,
// req.ip). Most routes ignore the error, some answer 500 on it; the old
// route says which.
//
// While an admin views the console as another account (impersonation),
// the entry is the admin's (ActorID) and is about the account viewed.
func (d *Deps) LogAction(r *http.Request, action, details string) error {
	if actor := ActorID(r); actor != UserID(r) {
		return d.Audit.WriteAbout(r.Context(), actor, UserID(r), action, details, ClientIP(r))
	}
	return d.Audit.Write(r.Context(), UserID(r), action, details, ClientIP(r))
}

// LogAccountAction is LogAction for an action about another account (or
// the account's own): the entry names target as the account it is about,
// so the account's history and its user page find it. The entry is the
// account's that acts (ActorID).
func (d *Deps) LogAccountAction(r *http.Request, target int64, action, details string) error {
	return d.Audit.WriteAbout(r.Context(), ActorID(r), target, action, details, ClientIP(r))
}

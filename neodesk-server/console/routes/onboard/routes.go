// Package onboard holds the routes of "Add a computer" and "Quick
// support":
//
//   - invites (join codes): made, listed, revoked and mailed by accounts
//     with enrollment.approve; redeemed by the client (POST
//     /api/onboard/join), which gets the server's addresses, its key and a
//     device token, and is approved, named and put into the invite's
//     folder.
//   - quick support sessions (support codes): made by accounts with
//     device.connect, one hour and one use; the quick support app redeems
//     the code and gets a session token that opens only its own session's
//     routes (/api/support/session...): report the device, the person's
//     consent, the session password for the supporter, the end.
//   - the public side of both: the page data behind /join/<code> and
//     /s/<code>, the client package under the code's file name (package
//     console/clientrelease), and the Linux scripts.
//
// Every route that takes a code from outside counts against one limit per
// address, and every code that cannot be used gets the same answer.
package onboard

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/console/admintoken"
	"github.com/neodeskapp/neodesk/neodesk-server/console/clientrelease"
	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/limits"
	"github.com/neodeskapp/neodesk/neodesk-server/console/onboard"
	"github.com/neodeskapp/neodesk/neodesk-server/console/serverinfo"
	"github.com/neodeskapp/neodesk/neodesk-server/logging"
)

// CodeLimit is how many requests with a code one address may send a
// minute: page data, downloads, scripts and redeems together.
const CodeLimit = 20

// SweepInterval is how often sessions are checked for their end.
const SweepInterval = 30 * time.Second

// HistoryDays is how long the record of an ended session is kept.
const HistoryDays = 90

type handlers struct {
	d        *kit.Deps
	codes    *onboard.Codes
	sessions *onboard.Sessions
	// callers is what the server answered the quick support apps about
	// their callers, for the helpers' viewers (A273)
	callers *onboard.CallerBook
	// feedback is the answers after quick support
	feedback *onboard.Feedback
	// thumbs are the helpers' pictures as the vouch answer carries them,
	// by account
	thumbMu  sync.Mutex
	thumbs   map[int64]thumb
	releases *clientrelease.Service
	limit    kit.Middleware
	log      *kit.Logger
	now      func() time.Time
}

// Options change what the group is built with; tests set them.
type Options struct {
	// Releases is the client release cache; nil builds one from the
	// configuration (data folder, environment).
	Releases *clientrelease.Service
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Register adds the group's routes.
func Register(d *kit.Deps) { RegisterWith(d, Options{}) }

// RegisterWith is Register with options.
func RegisterWith(d *kit.Deps, opts Options) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Releases == nil {
		getenv := func(string) string { return "" }
		dataDir := ""
		if d.Config != nil {
			dataDir = d.Config.DataDir
			if d.Config.Getenv != nil {
				getenv = d.Config.Getenv
			}
		}
		opts.Releases = clientrelease.New(clientrelease.Options{
			DataDir: dataDir,
			Getenv:  getenv,
			Logf:    func(format string, args ...any) { logging.Logf("console", format, args...) },
		})
	}
	h := &handlers{
		d:        d,
		codes:    onboard.NewCodes(d.GoAPI),
		sessions: onboard.NewSessions(d.GoAPI, opts.Now),
		callers:  onboard.NewCallerBook(opts.Now),
		feedback: onboard.NewFeedback(d.GoAPI),
		thumbs:   map[int64]thumb{},
		releases: opts.Releases,
		limit: limits.New(limits.Config{
			Name: "onboardCodeLimiter", WindowMs: 60_000, Max: CodeLimit,
			Message: refusal{Error: "Too many requests. Please try again in a minute.", Code: "rate_limited"},
			Key:     func(r *http.Request) string { return "onboard:" + kit.ClientIP(r) },
			Now:     opts.Now,
		}).Middleware,
		log: d.Log.Child("ONBOARD"),
		now: opts.Now,
	}
	// A quick support session made with an API token ends with the token:
	// its stored record ends in the token's transaction, the session the
	// console keeps in memory right after it
	if d.AdminTokens != nil {
		d.AdminTokens.OnEnd(func(ctx context.Context, e *admintoken.Ending) {
			if _, err := h.sessions.EndMadeWith(ctx, e.TokenID); err != nil {
				h.log.Warn("End the quick support sessions of an ended API token:", err)
			}
		})
	}
	approve := d.RequirePermission("enrollment.approve")
	connect := d.RequirePermission("device.connect")
	either := d.RequireAnyPermission("enrollment.approve", "device.connect")
	config := d.RequirePermission("server.config")

	r := d.Router
	r.Get("/api/onboard/status", h.status, d.RequireAuth, either)
	r.Get("/api/onboard/invites", h.listInvites, d.RequireAuth, approve)
	r.Post("/api/onboard/invites", h.createInvite, d.RequireAuth, approve)
	r.Get("/api/onboard/invites/{id}", h.getInvite, d.RequireAuth, approve)
	r.Delete("/api/onboard/invites/{id}", h.revokeInvite, d.RequireAuth, approve)
	r.Post("/api/onboard/invites/{id}/mail", h.mailInvite, d.RequireAuth, approve)
	r.Post("/api/onboard/devices/{id}/approve-key", h.approveKey, d.RequireAuth, approve)

	r.Get("/api/support/sessions", h.listSessions, d.RequireAuth, connect)
	r.Post("/api/support/sessions", h.createSession, d.RequireAuth, connect)
	r.Get("/api/support/sessions/{id}", h.getSession, d.RequireAuth, connect)
	r.Post("/api/support/sessions/{id}/password", h.takePassword, d.RequireAuth, connect)
	r.Delete("/api/support/sessions/{id}", h.endSession, d.RequireAuth, connect)
	r.Post("/api/support/sessions/{id}/mail", h.mailSession, d.RequireAuth, connect)
	r.Post("/api/support/devices/{id}/password", h.devicePassword, d.RequireAuth, connect)
	r.Post("/api/support/devices/{id}/caller", h.deviceCaller, d.RequireAuth, connect)
	r.Get("/api/support/feedback", h.listFeedback, d.RequireAuth, connect)
	r.Get("/api/support/feedback/form", h.getFeedbackForm, d.RequireAuth, config)
	r.Put("/api/support/feedback/form", h.saveFeedbackForm, d.RequireAuth, config)
	r.Get("/api/support/receiver-offer", h.getReceiverOffer, d.RequireAuth, config)
	r.Put("/api/support/receiver-offer", h.saveReceiverOffer, d.RequireAuth, config)

	r.Get("/api/onboard/public/{code}", h.publicCode, h.limit)
	r.Get("/api/onboard/public/{code}/download", h.download, h.limit)
	r.Get("/join/{code}", h.joinPage)
	r.Get("/join/{code}/install.sh", h.installScript, h.limit)
	r.Get("/s/{code}/run.sh", h.runScript, h.limit)

	// The clients' routes: no session, no CSRF token, the early stage.
	e := d.Early
	e.Post("/api/onboard/join", h.join, h.limit)
	e.Post("/api/support/redeem", h.redeemSupport, h.limit)
	e.Get("/api/support/session", h.appSession, h.requireSessionToken)
	e.Post("/api/support/session/device", h.appDevice, h.requireSessionToken)
	e.Post("/api/support/session/consent", h.appConsent, h.requireSessionToken)
	e.Post("/api/support/session/password", h.appPassword, h.requireSessionToken)
	e.Post("/api/support/session/end", h.appEnd, h.requireSessionToken)
	e.Post("/api/support/session/caller", h.appCaller, h.requireSessionToken)
	// A receiver asks whether the server vouches for an unattended caller
	// (A279); the device token's routes are on the main table, as the
	// device policy's
	r.Post("/api/nd/unattended/caller", h.unattendedCaller, d.RequireDeviceToken, d.RequireTokenDeviceMatch)
	d.Unattended.OnEnd(h.unattendedEnded)
	// Feedback works after the end too, for a session the person allowed
	e.Get("/api/support/session/feedback", h.appFeedbackForm, h.requireFeedbackToken)
	e.Post("/api/support/session/feedback", h.appFeedbackGive, h.requireFeedbackToken)

	if d.Jobs != nil {
		d.Jobs.Add("onboard sweep", h.sweepLoop)
	}
}

// thumb is a helper's scaled picture and the version it was made from.
type thumb struct{ version, url string }

// refusal is the answer of a request that did not work.
type refusal struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	// Reason is the machine-readable reason of a refused device, which
	// the client shows in its own words
	Reason string `json:"reason,omitempty"`
}

// fail answers {success:false, error, code}; error is the text of the
// request language for onboard.errors.<code>, the code itself without
// one.
func fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	text := kit.T(r, "onboard.errors."+code, nil)
	if text == "" || text == "onboard.errors."+code {
		text = code
	}
	kit.JSON(w, r, status, refusal{Error: text, Code: code})
}

// unusable is the one answer for a code that cannot be used.
func unusable(w http.ResponseWriter, r *http.Request) {
	kit.JSON(w, r, http.StatusNotFound, refusal{Error: onboard.ErrUnusable.Error()})
}

// serverError logs and answers 500.
func (h *handlers) serverError(w http.ResponseWriter, r *http.Request, what string, err error) {
	h.log.Error(what, err)
	fail(w, r, http.StatusInternalServerError, "server_error")
}

// consoleOf is the console's address for the links of a request: the
// public address of the settings (PANEL_PUBLIC_URL, PANEL_PUBLIC_HOST),
// else the address the request came to.
func (h *handlers) consoleOf(r *http.Request) onboard.Console {
	if h.d.Mail != nil {
		if c, ok := onboard.ParseConsole(h.d.Mail.GetPanelBaseURL()); ok {
			return c
		}
	}
	scheme := "http"
	if kit.Secure(r) {
		scheme = "https"
	}
	if c, ok := onboard.ParseConsole(scheme + "://" + r.Host); ok {
		return c
	}
	return onboard.Console{HTTPS: scheme == "https", Host: "localhost"}
}

// serverAnswer is how a client reaches this server.
type serverAnswer struct {
	IDServer    string `json:"id_server"`
	RelayServer string `json:"relay_server"`
	APIServer   string `json:"api_server"`
	Key         string `json:"key"`
}

func (h *handlers) serverOf(r *http.Request) serverAnswer {
	if h.d.ServerInfo == nil {
		return serverAnswer{}
	}
	ep := h.d.ServerInfo.ResolveRustDeskEndpoints(serverinfo.RequestHostOf(r), "")
	return serverAnswer{
		IDServer: ep.Host, RelayServer: ep.Relay, APIServer: ep.API,
		Key: string(h.d.ServerInfo.ResolvePublicKey(r.Context())),
	}
}

// serverName is the console's name as people see it.
func (h *handlers) serverName() string {
	if h.d.Branding != nil {
		return h.d.Branding.AppName("NeoDesk")
	}
	return "NeoDesk"
}

// personName is an account's first and last name, else its user name.
func (h *handlers) personName(ctx context.Context, userID int64, fallback string) string {
	if h.d.Store == nil || userID == 0 {
		return fallback
	}
	var first, last, username sql.NullString
	err := h.d.Store.QueryRow(ctx, `SELECT first_name, last_name, username FROM users WHERE id = ?`, userID).Scan(&first, &last, &username)
	if err != nil {
		return fallback
	}
	if name := strings.TrimSpace(strings.TrimSpace(first.String) + " " + strings.TrimSpace(last.String)); name != "" {
		return name
	}
	if username.String != "" {
		return username.String
	}
	return fallback
}

// sweepLoop ends sessions, removes the temporary devices of ended ones,
// prunes old records and expired codes, every SweepInterval until ctx
// ends, on the instance that holds the lease.
func (h *handlers) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !h.d.Held(kit.LeaseOnboardSweep) {
				continue
			}
			h.sweep(ctx)
		}
	}
}

// sweep is one run of sweepLoop.
func (h *handlers) sweep(ctx context.Context) {
	due, err := h.sessions.Sweep(ctx)
	if err != nil {
		h.log.Warn("Quick support sweep:", err)
	}
	for _, sess := range due {
		h.removeTemporaryDevice(ctx, sess)
	}
	if err := h.sessions.Prune(ctx, HistoryDays*24*time.Hour); err != nil {
		h.log.Warn("Quick support history prune:", err)
	}
	if err := h.codes.Prune(ctx); err != nil {
		h.log.Warn("Code prune:", err)
	}
}

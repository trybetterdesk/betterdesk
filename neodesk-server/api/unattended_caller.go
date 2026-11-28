package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/policy/unattended"
)

// Unattended callers (UNATTENDED-CONTRACT.md, A279): a receiver lets a
// relayed caller in without someone at the computer clicking Allow only
// when the server vouches for the caller. The receiver asks the console
// with its device token (POST /api/nd/unattended/caller, wire format in
// console/routes/onboard/PROTOCOL.md); the console asks this route which
// account opened the relay session and what the device's policy is, then
// checks the account and the rule itself.
//
// The relay session is the anchor, as for quick support callers: signal
// names the account on the ticket (the console's browser viewer with its
// console session, or a desktop app signed in with a client session
// token), the relay pairs exactly two sides on it, and a spent uuid is
// never issued again. One claim per uuid is shared with the quick support
// route, so a session is vouched once, whichever route asks.

// unattendedVia names who opened a relay session with an account.
const (
	viaConsole = "console"
	viaDesktop = "desktop"
)

// POST /api/unattended/caller with {device_id, session}, in process only:
// the account behind the live relay session to device_id and how it
// opened it, once per session and only in the session's first minute, with
// the device's inputs of the rule:
//
//	200 {account, via, mode, org_operators, access}
//	409 {error, account?}   session_not_open, too_late, already_used, no_account
//
// access is the device's access policy, null without one. account rides
// along on too_late and already_used when the session names one.
func (s *Server) handleUnattendedCaller(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID string `json:"device_id"`
		Session  string `json:"session"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	device, session := strings.TrimSpace(body.DeviceID), strings.TrimSpace(body.Session)
	if device == "" || session == "" || len(session) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_required"})
		return
	}
	refuse := func(code string, account int64) {
		out := map[string]any{"error": code}
		if account > 0 {
			out["account"] = account
		}
		writeJSON(w, http.StatusConflict, out)
	}
	pair, live := s.signinLive(session)
	if !live || pair.Target != device {
		refuse("session_not_open", 0)
		return
	}
	now := s.signinNow()
	if pair.Since.IsZero() || now.Sub(pair.Since) > supportCallerMaxAge {
		refuse("too_late", pair.Account)
		return
	}
	if !s.callerUses.claim(session, now) {
		refuse("already_used", pair.Account)
		return
	}
	via := ""
	switch {
	case pair.Account <= 0:
	case pair.Initiator == webRemoteInitiator:
		// The browser viewer of a signed-in console session; a guest's
		// bridge names no account and no console session
		if pair.ConsoleSession != "" {
			via = viaConsole
		}
	default:
		// A desktop app signed in to NeoDesk: signal took the account
		// from its client session token
		via = viaDesktop
	}
	if via == "" {
		refuse("no_account", 0)
		return
	}
	orgID, err := s.db.GetDeviceOrgID(device)
	if err != nil && !db.IsNoRows(err) {
		log.Printf("[unattended] organization of %s: %v", device, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	mode, operators := unattended.OrgInputs(s.orgPoliciesOf(orgID))
	if operators == nil {
		operators = []string{}
	}
	policy, err := s.db.GetAccessPolicy(device)
	if err != nil && !db.IsNoRows(err) {
		log.Printf("[unattended] access policy of %s: %v", device, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if err != nil {
		policy = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"account":       pair.Account,
		"via":           via,
		"mode":          mode,
		"org_operators": operators,
		"access":        unattended.FromDB(policy),
	})
}

// relayEndedHook is who hears that the relay ended a session: the console
// in this process, which writes the end of an unattended session it
// vouched for.
type relayEndedHook struct {
	fn atomic.Pointer[func(uuid string)]
}

// SetRelayEnded names who hears of the relay's session ends (the
// console's RelayEnded); nil for nobody.
func (s *Server) SetRelayEnded(fn func(uuid string)) {
	if fn == nil {
		s.relayEnded.fn.Store(nil)
		return
	}
	s.relayEnded.fn.Store(&fn)
}

// RelayEnded passes the relay's end of the session uuid on (the relay's
// SessionReporter calls it).
func (s *Server) RelayEnded(uuid string) {
	if s == nil {
		return
	}
	if fn := s.relayEnded.fn.Load(); fn != nil {
		(*fn)(uuid)
	}
}

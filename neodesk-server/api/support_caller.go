package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Quick support callers (A271): the quick support app lets the person
// accept a connection by click only when the server vouches that the
// connection is a signed-in helper's browser viewer. The app asks the
// console with its session token (POST /api/support/session/caller, wire
// format in console/routes/onboard/PROTOCOL.md); the console asks this
// route which account the relay session belongs to, then checks that
// account itself.
//
// The relay session is the proof's anchor: signal issues its ticket only
// to the console's web client of a signed-in account (the panel proof
// names the account and its browser session), the relay pairs exactly two
// sides on it, and a consumed uuid is never issued again. The device knows
// the uuid from signal's RequestRelay, not from the caller.

// supportCallerMaxAge is how long after both sides met on the relay the
// server still vouches for the session's caller.
const supportCallerMaxAge = 60 * time.Second

func (s *Server) supportCallerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/support/caller", s.inProcessOnly(s.handleSupportCaller))
	mux.HandleFunc("POST /api/unattended/caller", s.inProcessOnly(s.handleUnattendedCaller))
}

// POST /api/support/caller with {device_id, session}: the console account
// whose browser viewer opened the live relay session to device_id, once
// per session and only in the session's first minute. Refusals are 409
// with error session_not_open (no live session to this device from a
// signed-in browser viewer), too_late or already_used.
func (s *Server) handleSupportCaller(w http.ResponseWriter, r *http.Request) {
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
	refuse := func(code string) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": code})
	}
	pair, live := s.signinLive(session)
	if !live || pair.Target != device || pair.Initiator != webRemoteInitiator || pair.Account <= 0 || pair.ConsoleSession == "" {
		refuse("session_not_open")
		return
	}
	now := s.signinNow()
	if pair.Since.IsZero() || now.Sub(pair.Since) > supportCallerMaxAge {
		refuse("too_late")
		return
	}
	if !s.callerUses.claim(session, now) {
		refuse("already_used")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": pair.Account})
}

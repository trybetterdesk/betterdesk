package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/relay"
)

// TestUnattendedCallerNamesTheAccountAndHowItCame: the API server tells
// the console which account opened a live relay session to the device
// (UNATTENDED-CONTRACT.md): only for a session to that device, in its
// first minute, once (shared with the quick support claim), and only for
// a browser viewer of a console session (via console) or a desktop app
// signed in to NeoDesk (via desktop). The answer carries the device's
// inputs of the rule.
func TestUnattendedCallerNamesTheAccountAndHowItCame(t *testing.T) {
	srv, database := newInternalServer(t, nil)
	now := time.Unix(1_800_000_000, 0)
	srv.now = func() time.Time { return now }
	fresh := now.Add(-10 * time.Second)
	srv.signinLiveFn = func(uuid string) (relay.LivePair, bool) {
		pairs := map[string]relay.LivePair{
			"u-console":   {Initiator: webRemoteInitiator, Target: "PEERAAA1", Account: 5, ConsoleSession: "console-1", Since: fresh},
			"u-desktop":   {Initiator: "session-user-5", Target: "PEERAAA1", Account: 5, Since: fresh},
			"u-quick":     {Initiator: webRemoteInitiator, Target: "PEERAAA1", Account: 5, ConsoleSession: "console-1", Since: fresh},
			"u-other":     {Initiator: webRemoteInitiator, Target: "PEERBBB2", Account: 5, ConsoleSession: "console-1", Since: fresh},
			"u-guest":     {Initiator: webRemoteInitiator, Target: "PEERAAA1", Account: 0, Since: fresh},
			"u-nobrowser": {Initiator: webRemoteInitiator, Target: "PEERAAA1", Account: 5, Since: fresh},
			"u-anon":      {Initiator: "123456789", Target: "PEERAAA1", Account: 0, Since: fresh},
			"u-old":       {Initiator: webRemoteInitiator, Target: "PEERAAA1", Account: 5, ConsoleSession: "console-1", Since: now.Add(-61 * time.Second)},
			"u-nodate":    {Initiator: webRemoteInitiator, Target: "PEERAAA1", Account: 5, ConsoleSession: "console-1"},
		}
		p, ok := pairs[uuid]
		return p, ok
	}
	ask := func(session string) (int, map[string]any) {
		t.Helper()
		status, body := asConsole(t, srv, http.MethodPost, "/api/unattended/caller", `{"device_id":"PEERAAA1","session":"`+session+`"}`)
		var out map[string]any
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("%s: %d %s is no JSON", session, status, body)
		}
		return status, out
	}
	for _, c := range []struct {
		session, want string
		account       float64
		why           string
	}{
		{"no-such-session", "session_not_open", 0, "no proof: a session that does not run"},
		{"u-other", "session_not_open", 0, "a proof for another device"},
		{"u-old", "too_late", 5, "a session that met on the relay over a minute ago"},
		{"u-nodate", "too_late", 5, "a session without a start"},
		{"u-guest", "no_account", 0, "a guest's bridge without a console session"},
		{"u-nobrowser", "no_account", 0, "the web client without a console session"},
		{"u-anon", "no_account", 0, "a desktop app that is not signed in"},
	} {
		status, out := ask(c.session)
		got, _ := out["account"].(float64)
		if status != http.StatusConflict || out["error"] != c.want || got != c.account {
			t.Errorf("%s: %d %v, want 409 %s with account %v", c.why, status, out, c.want, c.account)
		}
	}

	// The device's rule inputs: its organization's mode and operators,
	// and its access policy
	if err := database.CreateOrganization(&db.Organization{ID: "org-u", Name: "Org U"}); err != nil {
		t.Fatal(err)
	}
	if err := database.AssignDeviceToOrg(&db.OrgDevice{OrgID: "org-u", DeviceID: "PEERAAA1"}); err != nil {
		t.Fatal(err)
	}
	if err := database.SetOrgSetting("org-u", "policy_connection", `{"mode":"unattended"}`); err != nil {
		t.Fatal(err)
	}
	if err := database.SetOrgSetting("org-u", "policy_security", `{"allowed_operators":["anna","ben"]}`); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAccessPolicy(&db.AccessPolicy{PeerID: "PEERAAA1", UnattendedEnabled: true, AllowedOperators: "anna"}); err != nil {
		t.Fatal(err)
	}
	status, out := ask("u-console")
	got, _ := json.Marshal(out)
	if status != http.StatusOK || string(got) != `{"access":{"allowed_operators":["anna"],"schedule_days":[],"schedule_enabled":false,"schedule_end":"","schedule_start":"","schedule_timezone":"","unattended_enabled":true},"account":5,"mode":"unattended","org_operators":["anna","ben"],"via":"console"}` {
		t.Fatalf("the browser viewer's session: %d %s", status, got)
	}
	if status, out := ask("u-console"); status != http.StatusConflict || out["error"] != "already_used" || out["account"] != float64(5) {
		t.Errorf("the same session again: %d %v, want 409 already_used", status, out)
	}

	if err := database.DeleteAccessPolicy("PEERAAA1"); err != nil {
		t.Fatal(err)
	}
	status, out = ask("u-desktop")
	if status != http.StatusOK || out["via"] != "desktop" || out["account"] != float64(5) || out["access"] != nil {
		t.Fatalf("the signed-in desktop app's session: %d %v, want via desktop and no access policy", status, out)
	}

	// One claim per session, whichever route asks first
	if status, body := asConsole(t, srv, http.MethodPost, "/api/support/caller", `{"device_id":"PEERAAA1","session":"u-quick"}`); status != http.StatusOK {
		t.Fatalf("quick support's claim: %d %s", status, body)
	}
	if status, out := ask("u-quick"); status != http.StatusConflict || out["error"] != "already_used" {
		t.Errorf("a session quick support vouched for: %d %v, want 409 already_used", status, out)
	}

	// Only the console in this process asks; the API port answers 404
	if status, body := listenerCall(t, srv, http.MethodPost, "/api/unattended/caller", `{"device_id":"PEERAAA1","session":"u-desktop"}`,
		map[string]string{"X-API-Key": testAPIKey}); status != http.StatusNotFound {
		t.Errorf("on the listener: %d %s, want 404", status, body)
	}
	if status, _ := asConsole(t, srv, http.MethodPost, "/api/unattended/caller", `{"device_id":"PEERAAA1","session":""}`); status != http.StatusBadRequest {
		t.Errorf("no session: %d, want 400", status)
	}
	if status, _ := asConsole(t, srv, http.MethodPost, "/api/unattended/caller", `{"device_id":"PEERAAA1","session":"`+strings.Repeat("x", 129)+`"}`); status != http.StatusBadRequest {
		t.Errorf("a session id of 129 characters: %d, want 400", status)
	}
}

// TestRelayEndedReachesTheHook: the relay's end of a session reaches who
// the console named, and nobody once it is gone.
func TestRelayEndedReachesTheHook(t *testing.T) {
	srv, _ := newInternalServer(t, nil)
	var got []string
	srv.RelayEnded("before")
	srv.SetRelayEnded(func(uuid string) { got = append(got, uuid) })
	srv.RelayEnded("one")
	srv.SetRelayEnded(nil)
	srv.RelayEnded("after")
	var none *Server
	none.RelayEnded("no server")
	if strings.Join(got, ",") != "one" {
		t.Fatalf("the hook heard %v, want one", got)
	}
}

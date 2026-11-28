package onboard_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/console/store"
	"github.com/neodeskapp/neodesk/neodesk-server/console/store/storetest"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
)

// receiver is an enrolled receiver with its device token, asking the
// console about its callers.
type receiver struct {
	w      *world
	device string
	token  string
}

// newReceiver enrolls device (a peer row and a device token) with an
// access policy that turns unattended access on.
func (w *world) newReceiver(t *testing.T, device string) *receiver {
	t.Helper()
	if err := w.gdb.UpsertPeer(&db.Peer{ID: device, Hostname: "front-desk", Status: "ONLINE"}); err != nil {
		t.Fatal(err)
	}
	if err := w.gdb.SaveAccessPolicy(&db.AccessPolicy{PeerID: device, UnattendedEnabled: true}); err != nil {
		t.Fatal(err)
	}
	token, err := w.deps.Authn.IssueDeviceToken(context.Background(), device, "test")
	if err != nil || token == "" {
		t.Fatalf("device token: %q %v", token, err)
	}
	return &receiver{w: w, device: device, token: token}
}

// ask is POST /api/nd/unattended/caller over HTTPS (through the trusted
// proxy) or plain HTTP.
func (rc *receiver) ask(session string, https bool, header ...string) answer {
	rc.w.t.Helper()
	h := []string{"Authorization", "Bearer " + rc.token, "X-Device-Id", rc.device}
	if https {
		h = append(h, "X-Forwarded-Proto", "https")
	}
	return rc.w.app().do(http.MethodPost, "/api/nd/unattended/caller", `{"session":"`+session+`"}`, append(h, header...)...)
}

// inOrg puts the device into an organization with policies.
func (w *world) inOrg(t *testing.T, device string, policies map[string]string) {
	t.Helper()
	org := "org-" + device
	if err := w.gdb.CreateOrganization(&db.Organization{ID: org, Name: "Org " + device, Slug: org}); err != nil {
		t.Fatal(err)
	}
	if err := w.gdb.AssignDeviceToOrg(&db.OrgDevice{OrgID: org, DeviceID: device}); err != nil {
		t.Fatal(err)
	}
	for group, value := range policies {
		if err := w.gdb.SetOrgSetting(org, "policy_"+group, value); err != nil {
			t.Fatal(err)
		}
	}
}

// addAccount adds a console account with the role.
func (w *world) addAccount(t *testing.T, id int64, username, role string) {
	t.Helper()
	if _, err := w.db.Exec(context.Background(), "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, 'x', ?)", id, username, role); err != nil {
		t.Fatal(err)
	}
}

func refusedWith(t *testing.T, why string, res answer, reason string) {
	t.Helper()
	if res.status != http.StatusConflict || str(res.json(t), "error") != "not_vouched" || str(res.json(t), "reason") != reason {
		t.Errorf("%s: %d %s, want 409 not_vouched %s", why, res.status, res.body, reason)
	}
}

func auditCount(t *testing.T, sdb *store.DB, action string, about int64) int {
	t.Helper()
	var n int
	if err := sdb.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_log WHERE action = ? AND target_user_id = ?`, action, about).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestUnattendedCallerVouchesForAStaffAccount: a receiver asks about a
// relayed caller (UNATTENDED-CONTRACT.md). The server vouches, names the
// helper and writes the audit entry about the account first, for the
// browser viewer of a console session and for a desktop app signed in to
// NeoDesk, once per relay session. The end of the relay session writes
// the end with its duration.
func TestUnattendedCallerVouchesForAStaffAccount(t *testing.T) {
	storetest.EachMigrated(t, func(t *testing.T, sdb *store.DB) {
		w := newWorld(t, sdb)
		suffix := strings.ReplaceAll(t.Name(), "/", "-")
		rc := w.newReceiver(t, "623456781")

		viewer := "viewer-" + suffix
		liveRelay(t, viewer, "panel-web-remote", rc.device, 5, "console-1")
		res := rc.ask(viewer, true)
		if res.status != http.StatusOK {
			t.Fatalf("the browser viewer: %d %s", res.status, res.body)
		}
		got := res.json(t)
		if got["vouched"] != true || str(got, "helper") != "Olga Operator" || str(got, "helper_username") != "e2e_operator" ||
			str(got, "device_id") != rc.device || str(got, "session") != viewer || str(got, "via") != "console" {
			t.Fatalf("the browser viewer: %s", res.body)
		}
		var who, about int64
		var details string
		if err := sdb.QueryRow(context.Background(), `SELECT user_id, target_user_id, details FROM audit_log WHERE action = 'unattended_session_started'`).Scan(&who, &about, &details); err != nil {
			t.Fatal(err)
		}
		if who != 5 || about != 5 || !strings.Contains(details, "device "+rc.device) || !strings.Contains(details, "via=console") || !strings.Contains(details, "relay_session="+viewer) {
			t.Errorf("audit entry by %d about %d: %q", who, about, details)
		}
		// Once per relay session: a replay is refused and noted
		refusedWith(t, "the same relay session again", rc.ask(viewer, true), "already_used")
		if n := auditCount(t, sdb, "unattended_caller_refused", 5); n != 1 {
			t.Errorf("the replay's audit entries: %d, want 1", n)
		}

		desktop := "desktop-" + suffix
		liveRelay(t, desktop, "session-user-5", rc.device, 5, "")
		res = rc.ask(desktop, true)
		if res.status != http.StatusOK || str(res.json(t), "via") != "desktop" || str(res.json(t), "helper_username") != "e2e_operator" {
			t.Fatalf("the signed-in desktop app: %d %s", res.status, res.body)
		}

		// The relay ends the viewer's session: the end with its duration
		w.deps.Unattended.End(viewer)
		w.deps.Unattended.End(viewer)
		w.deps.Unattended.End("never-vouched-" + suffix)
		var n int
		if err := sdb.QueryRow(context.Background(), `SELECT COUNT(*), COALESCE(MAX(details), '') FROM audit_log WHERE action = 'unattended_session_ended' AND user_id = 5 AND target_user_id = 5`).Scan(&n, &details); err != nil {
			t.Fatal(err)
		}
		if n != 1 || !strings.Contains(details, "device "+rc.device) || !strings.Contains(details, "duration_s=") || !strings.Contains(details, "relay_session="+viewer) {
			t.Errorf("end entries: %d %q, want one with the device, duration and relay session", n, details)
		}
	})
}

// TestUnattendedCallerRefusesEachCheck: every check of the contract
// refuses on its own, with its reason, and a refusal with an account is
// in the audit log.
func TestUnattendedCallerRefusesEachCheck(t *testing.T) {
	sdb := storetest.Migrated(t)
	w := newWorld(t, sdb)
	suffix := strings.ReplaceAll(t.Name(), "/", "-")
	w.addAccount(t, 20, "scoped_op", "operator")
	w.addAccount(t, 21, "gone_op", "operator")
	if _, err := w.db.Exec(context.Background(), "UPDATE users SET disabled = ? WHERE id = 21", true); err != nil {
		t.Fatal(err)
	}
	// A device group with an access list closes 723456712 to everyone
	// but Olga, so scoped_op does not see it
	for _, q := range []string{
		`INSERT INTO device_groups (guid, name, note, team_id, source_type, tag_filter) VALUES ('g-closed', 'Closed', '', '', 'manual', '')`,
		`INSERT INTO device_group_user_access (device_group_id, user_id) SELECT id, 5 FROM device_groups WHERE guid = 'g-closed'`,
		`INSERT INTO device_group_members (device_group_id, peer_id) SELECT id, '723456712' FROM device_groups WHERE guid = 'g-closed'`,
	} {
		if _, err := w.db.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	notToday := time.Now().UTC().AddDate(0, 0, 1).Weekday()
	day := [...]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}[notToday]

	type check struct {
		name   string
		device string
		setup  func(rc *receiver)
		// relay: initiator, account, console session; "" initiator for
		// no live session
		initiator string
		account   int64
		console   string
		https     bool
		reason    string
	}
	checks := []check{
		{name: "plain HTTP", device: "723456701", initiator: "panel-web-remote", account: 5, console: "console-1", reason: "not_https"},
		{name: "no proof: an unknown session", device: "723456702", reason: "session_not_open", https: true},
		{name: "a proof for another device", device: "723456703", initiator: "panel-web-remote", account: 5, console: "console-1", https: true, reason: "session_not_open",
			setup: func(rc *receiver) { rc.device = "723456713"; rc.w.newReceiver(rc.w.t, "723456713") }},
		{name: "a guest's bridge without a console session", device: "723456704", initiator: "panel-web-remote", https: true, reason: "no_account"},
		{name: "a desktop app that is not signed in", device: "723456705", initiator: "828416401", https: true, reason: "no_account"},
		{name: "the web client without a console session", device: "723456715", initiator: "panel-web-remote", account: 5, https: true, reason: "no_account"},
		{name: "outside the schedule", device: "723456706", initiator: "panel-web-remote", account: 5, console: "console-1", https: true, reason: "outside_schedule",
			setup: func(rc *receiver) {
				_ = rc.w.gdb.SaveAccessPolicy(&db.AccessPolicy{PeerID: rc.device, UnattendedEnabled: true, ScheduleEnabled: true, ScheduleDays: day,
					ScheduleStartTime: "00:00", ScheduleEndTime: "00:00", ScheduleTimezone: "UTC"})
			}},
		{name: "not in the device's operators", device: "723456707", initiator: "panel-web-remote", account: 5, console: "console-1", https: true, reason: "operator_not_allowed",
			setup: func(rc *receiver) {
				_ = rc.w.gdb.SaveAccessPolicy(&db.AccessPolicy{PeerID: rc.device, UnattendedEnabled: true, AllowedOperators: "anna,ben"})
			}},
		{name: "not in the organization's operators", device: "723456708", initiator: "panel-web-remote", account: 5, console: "console-1", https: true, reason: "operator_not_allowed",
			setup: func(rc *receiver) {
				rc.w.inOrg(rc.w.t, rc.device, map[string]string{"security": `{"allowed_operators":["anna"]}`})
			}},
		{name: "the policy asks always", device: "723456709", initiator: "panel-web-remote", account: 5, console: "console-1", https: true, reason: "ask_always",
			setup: func(rc *receiver) {
				rc.w.inOrg(rc.w.t, rc.device, map[string]string{"connection": `{"mode":"ask_always"}`})
			}},
		{name: "attended without unattended access on the device", device: "723456710", initiator: "panel-web-remote", account: 5, console: "console-1", https: true, reason: "not_enabled",
			setup: func(rc *receiver) {
				rc.w.inOrg(rc.w.t, rc.device, map[string]string{"connection": `{"mode":"attended"}`})
				_ = rc.w.gdb.SaveAccessPolicy(&db.AccessPolicy{PeerID: rc.device, UnattendedEnabled: false})
			}},
		{name: "an account without Connect to devices", device: "723456711", initiator: "panel-web-remote", account: 6, console: "console-6", https: true, reason: "no_permission"},
		{name: "an account that does not see the device", device: "723456712", initiator: "panel-web-remote", account: 20, console: "console-20", https: true, reason: "no_permission"},
		{name: "a disabled account", device: "723456714", initiator: "session-user-21", account: 21, https: true, reason: "no_permission"},
	}
	for _, c := range checks {
		rc := w.newReceiver(t, c.device)
		target := c.device
		if c.setup != nil {
			c.setup(rc)
			rc.device = c.device
		}
		if c.name == "a proof for another device" {
			target = "723456713"
		}
		session := "check-" + c.device + "-" + suffix
		if c.initiator != "" {
			liveRelay(t, session, c.initiator, target, c.account, c.console)
		}
		refusedWith(t, c.name, rc.ask(session, c.https), c.reason)
	}
	// A refusal with an account goes to the audit log, about the account
	for account, want := range map[int64]int{5: 5, 6: 1, 20: 1, 21: 1} {
		if n := auditCount(t, sdb, "unattended_caller_refused", account); n != want {
			t.Errorf("refusals about account %d: %d, want %d", account, n, want)
		}
	}
	if n := auditCount(t, sdb, "unattended_session_started", 5); n != 0 {
		t.Errorf("a refused caller has %d start entries", n)
	}

	// Plain HTTP did not spend the relay session: over HTTPS it vouches
	if res := (&receiver{w: w, device: "723456701", token: w.tokenOf(t, "723456701")}).ask("check-723456701-"+suffix, true); res.status != http.StatusOK {
		t.Errorf("over HTTPS after a plain refusal: %d %s", res.status, res.body)
	}
}

// tokenOf issues a new device token for the device.
func (w *world) tokenOf(t *testing.T, device string) string {
	t.Helper()
	token, err := w.deps.Authn.IssueDeviceToken(context.Background(), device, "test")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// TestUnattendedCallerNeedsTheDevicesToken: only the token of the device
// asks, and a banned or soft-deleted device's token proves nothing.
func TestUnattendedCallerNeedsTheDevicesToken(t *testing.T) {
	sdb := storetest.Migrated(t)
	w := newWorld(t, sdb)
	suffix := strings.ReplaceAll(t.Name(), "/", "-")
	ctx := context.Background()

	rc := w.newReceiver(t, "823456781")
	session := "token-" + suffix
	liveRelay(t, session, "panel-web-remote", rc.device, 5, "console-1")
	if res := w.app().do(http.MethodPost, "/api/nd/unattended/caller", `{"session":"`+session+`"}`, "X-Forwarded-Proto", "https"); res.status != http.StatusUnauthorized {
		t.Errorf("without a token: %d %s, want 401", res.status, res.body)
	}
	if res := rc.ask(session, true, "X-Device-Id", "823456789"); res.status != http.StatusForbidden {
		t.Errorf("naming another device: %d %s, want 403", res.status, res.body)
	}

	for _, c := range []struct{ name, device, column string }{
		{"a banned device", "823456782", "banned"},
		{"a soft-deleted device", "823456783", "soft_deleted"},
	} {
		other := w.newReceiver(t, c.device)
		relaySession := c.column + "-" + suffix
		liveRelay(t, relaySession, "panel-web-remote", c.device, 5, "console-1")
		// The flag alone, without the revocation that comes with a ban
		// or a delete, so the token itself stays good
		if _, err := w.db.Exec(ctx, "UPDATE peers SET "+c.column+" = ? WHERE id = ?", true, c.device); err != nil {
			t.Fatal(err)
		}
		if res := other.ask(relaySession, true); res.status != http.StatusUnauthorized {
			t.Errorf("%s: %d %s, want 401", c.name, res.status, res.body)
		}
	}
	// The refusals spent nothing: the good device's session still vouches
	if res := rc.ask(session, true); res.status != http.StatusOK {
		t.Errorf("the device's own token: %d %s", res.status, res.body)
	}
}

// TestUnattendedCallerWritesTheLogFirst: when the start can't go into the
// audit log, nobody is vouched for (500), as the contract says.
func TestUnattendedCallerWritesTheLogFirst(t *testing.T) {
	sdb := storetest.Migrated(t)
	w := newWorld(t, sdb)
	rc := w.newReceiver(t, "923456781")
	session := "nolog-" + strings.ReplaceAll(t.Name(), "/", "-")
	liveRelay(t, session, "panel-web-remote", rc.device, 5, "console-1")
	if _, err := w.db.Exec(context.Background(), "ALTER TABLE audit_log RENAME TO audit_log_gone"); err != nil {
		t.Fatal(err)
	}
	res := rc.ask(session, true)
	if res.status != http.StatusInternalServerError || str(res.json(t), "error") != "audit_failed" {
		t.Fatalf("without an audit log: %d %s, want 500 audit_failed", res.status, res.body)
	}
}

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/peer"
)

// adminPolicy is a policy as an admin saved it.
func adminPolicy(id string) *db.AccessPolicy {
	return &db.AccessPolicy{
		PeerID: id, UnattendedEnabled: true, ScheduleEnabled: true, ScheduleDays: "mon,tue,wed,thu,fri",
		ScheduleStartTime: "08:00", ScheduleEndTime: "18:00", ScheduleTimezone: "Europe/Berlin",
		AllowedOperators: "anna,ben", UpdatedBy: "admin", UpdatedAt: "2026-11-01T10:00:00Z",
	}
}

// TestDeviceSelfAccessPolicyKeepsTheAdminsPolicy: a device that says
// whether it keeps a local password changes only that marker. The
// admin's unattended switch, schedule, allowed operators and who saved
// them stay as they are, whatever the device sends for unattended_enabled.
func TestDeviceSelfAccessPolicyKeepsTheAdminsPolicy(t *testing.T) {
	database := testSetupDB(t)
	defer database.Close()
	const deviceID = "BD-SELF-KEEPS"
	if err := database.UpsertPeer(&db.Peer{ID: deviceID, Status: "ONLINE", DeviceType: "os_agent"}); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAccessPolicy(adminPolicy(deviceID)); err != nil {
		t.Fatal(err)
	}
	srv := New(config.DefaultConfig(), database, peer.NewMap(), nil, "test")
	token, err := srv.issueEnrollmentDeviceToken(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	post := func(passwordSet, unattended bool) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"device_id": deviceID, "device_token": token, "password_set": passwordSet, "unattended_enabled": unattended})
		rec := httptest.NewRecorder()
		srv.handleDeviceSelfAccessPolicy(rec, httptest.NewRequest(http.MethodPost, "/api/devices/self/access-policy", bytes.NewReader(raw)))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("self route: %d %s", rec.Code, rec.Body.String())
		}
	}
	check := func(when string, passwordSet bool) {
		t.Helper()
		got, err := database.GetAccessPolicy(deviceID)
		if err != nil {
			t.Fatal(err)
		}
		want := adminPolicy(deviceID)
		if got.UnattendedEnabled != want.UnattendedEnabled || got.ScheduleEnabled != want.ScheduleEnabled || got.ScheduleDays != want.ScheduleDays ||
			got.ScheduleStartTime != want.ScheduleStartTime || got.ScheduleEndTime != want.ScheduleEndTime || got.ScheduleTimezone != want.ScheduleTimezone ||
			got.AllowedOperators != want.AllowedOperators || got.UpdatedBy != want.UpdatedBy {
			t.Errorf("%s: the admin's policy changed: %+v", when, got)
		}
		if got.PasswordSet != passwordSet {
			t.Errorf("%s: password_set %v, want %v", when, got.PasswordSet, passwordSet)
		}
	}
	post(true, false)
	check("after a device with a password", true)
	post(false, false)
	check("after a device without a password", false)

	// A device without a policy that keeps no password gets none; one
	// with a password gets a policy that only carries the marker
	const bare = "BD-SELF-BARE"
	if err := database.UpsertPeer(&db.Peer{ID: bare, Status: "ONLINE", DeviceType: "os_agent"}); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAccessPolicyPasswordMarker(bare, false); err != nil {
		t.Fatal(err)
	}
	if p, err := database.GetAccessPolicy(bare); err == nil {
		t.Fatalf("a device without a password got a policy: %+v", p)
	} else if !db.IsNoRows(err) {
		t.Fatalf("no policy must be no rows: %v", err)
	}
	if err := database.SetAccessPolicyPasswordMarker(bare, true); err != nil {
		t.Fatal(err)
	}
	if p, err := database.GetAccessPolicy(bare); err != nil || !p.PasswordSet || p.UnattendedEnabled || p.ScheduleEnabled {
		t.Fatalf("marker only: %+v %v", p, err)
	}
}

// TestSaveAccessPolicyRecordsTheAccountAndTime: the admin's save stores
// the account that saved it and when, not the caller's address, and
// refuses a time zone the caller check does not know.
func TestSaveAccessPolicyRecordsTheAccountAndTime(t *testing.T) {
	database := testSetupDB(t)
	defer database.Close()
	const deviceID = "BD-ADMIN-PUT"
	if err := database.UpsertPeer(&db.Peer{ID: deviceID, Status: "ONLINE"}); err != nil {
		t.Fatal(err)
	}
	srv := New(config.DefaultConfig(), database, peer.NewMap(), nil, "test")
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/peers/"+deviceID+"/access-policy", bytes.NewBufferString(body))
		req.SetPathValue("id", deviceID)
		req.RemoteAddr = "203.0.113.9:4444"
		req = req.WithContext(context.WithValue(req.Context(), ctxKeyUsername, "alice"))
		rec := httptest.NewRecorder()
		srv.handleSaveAccessPolicy(rec, req)
		return rec
	}
	before := time.Now().UTC().Add(-time.Second)
	rec := put(`{"unattended_enabled":true,"schedule_enabled":true,"schedule_days":"mon","schedule_start_time":"08:00","schedule_end_time":"18:00","schedule_timezone":"Europe/Berlin","allowed_operators":"anna"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	got, err := database.GetAccessPolicy(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UpdatedBy != "alice" {
		t.Errorf("updated_by %q, want the account alice", got.UpdatedBy)
	}
	at, err := time.Parse(time.RFC3339, got.UpdatedAt)
	if err != nil || at.Before(before.Truncate(time.Second)) {
		t.Errorf("updated_at %q (%v), want the time of the save", got.UpdatedAt, err)
	}

	for _, tz := range []string{"Europe/Atlantis", "Local", "+01:00"} {
		rec = put(`{"unattended_enabled":true,"schedule_enabled":true,"schedule_days":"mon","schedule_start_time":"08:00","schedule_end_time":"18:00","schedule_timezone":"` + tz + `"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("time zone %q: %d %s, want 400", tz, rec.Code, rec.Body.String())
		}
	}
	if got, _ := database.GetAccessPolicy(deviceID); got.ScheduleTimezone != "Europe/Berlin" {
		t.Errorf("a refused save changed the time zone to %q", got.ScheduleTimezone)
	}
}

// TestAccessPolicyOnlyInTheSealedHeartbeat: the plain heartbeat answer
// carries no access policy; the sealed one carries all of it, with the
// days and the operators as lists, and the defaults for a device without
// a policy.
func TestAccessPolicyOnlyInTheSealedHeartbeat(t *testing.T) {
	srv, deviceID, deviceUUID, priv, responsePub, responsePriv := newConnectionModeFixture(t)
	if err := srv.db.SaveAccessPolicy(adminPolicy(deviceID)); err != nil {
		t.Fatal(err)
	}
	if err := srv.db.SetAccessPolicyPasswordMarker(deviceID, true); err != nil {
		t.Fatal(err)
	}

	// Plain: an unsealed heartbeat of the same device
	raw, _ := json.Marshal(map[string]any{"id": deviceID, "uuid": deviceUUID})
	req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(raw))
	req.RemoteAddr = "198.51.100.10:1234"
	rec := httptest.NewRecorder()
	srv.handleClientHeartbeat(rec, req)
	if bytes.Contains(rec.Body.Bytes(), []byte("access_policy")) {
		t.Fatalf("the plain answer carries the access policy: %s", rec.Body.String())
	}

	sealed := openSealedHeartbeat(t, srv, postHeartbeat(t, srv, deviceID, deviceUUID,
		sealClientHeartbeat(t, srv, deviceID, priv, 1, desktopIdentity(deviceID, deviceUUID, "normal"), responsePub)), responsePriv)
	got, _ := json.Marshal(sealed["access_policy"])
	want := `{"allowed_operators":["anna","ben"],"password_set":true,"schedule_days":["mon","tue","wed","thu","fri"],"schedule_enabled":true,"schedule_end":"18:00","schedule_start":"08:00","schedule_timezone":"Europe/Berlin","unattended_enabled":true}`
	if string(got) != want {
		t.Fatalf("sealed access_policy\n got %s\nwant %s", got, want)
	}

	if err := srv.db.DeleteAccessPolicy(deviceID); err != nil {
		t.Fatal(err)
	}
	sealed = openSealedHeartbeat(t, srv, postHeartbeat(t, srv, deviceID, deviceUUID,
		sealClientHeartbeat(t, srv, deviceID, priv, 2, desktopIdentity(deviceID, deviceUUID, "normal"), responsePub)), responsePriv)
	got, _ = json.Marshal(sealed["access_policy"])
	want = `{"allowed_operators":[],"password_set":false,"schedule_days":[],"schedule_enabled":false,"schedule_end":"","schedule_start":"","schedule_timezone":"","unattended_enabled":false}`
	if string(got) != want {
		t.Fatalf("sealed access_policy without a policy\n got %s\nwant %s", got, want)
	}
}

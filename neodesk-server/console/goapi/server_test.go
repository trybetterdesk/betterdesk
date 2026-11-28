package goapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/console/goapi/internal/apitest"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
)

// realClient returns a client on a real API server with two peers.
func realClient(t *testing.T) (*Client, *apitest.Server) {
	t.Helper()
	srv := apitest.New(t)
	seen := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range []*db.Peer{
		{ID: "PEERAAA1", UUID: "uuid-a", Hostname: "host-a", OS: "Windows", Version: "1.4.6", User: "alice", Note: "n1", Tags: "t1,t2", Status: "OFFLINE", LastOnline: seen},
		{ID: "PEERBBB2", UUID: "uuid-b", Hostname: "host-b", OS: "Linux", Version: "1.4.6", Status: "OFFLINE", LastOnline: seen},
	} {
		if err := srv.DB.UpsertPeer(p); err != nil {
			t.Fatalf("seed peer: %v", err)
		}
	}
	return New(srv.API.InternalHandler(), WithEventBus(srv.Bus), WithTimeout(time.Minute)), srv
}

func wantJSON(t *testing.T, what string, got any, want string) {
	t.Helper()
	if g := toJSON(t, got); g != want {
		t.Errorf("%s = %s\n  want %s", what, g, want)
	}
}

// wantAt checks one value inside a result, by its path.
func wantAt(t *testing.T, what string, v any, want string, path ...any) {
	t.Helper()
	if g := toJSON(t, Dig(v, path...)); g != want {
		t.Errorf("%s: %v = %s, want %s (in %s)", what, path, g, want, toJSON(t, v))
	}
}

const notFound404 = `{"success":false,"error":"Request failed with status code 404"}`
const badRequest400 = `{"success":false,"error":"Request failed with status code 400"}`

// TestAgainstAPIServer runs the methods against the real handlers. The
// steps share one server, in order: opening a database takes seconds.
func TestAgainstAPIServer(t *testing.T) {
	c, srv := realClient(t)
	ctx := context.Background()

	t.Run("health and statistics", func(t *testing.T) {
		health := c.GetHealth(ctx)
		wantAt(t, "GetHealth", health, `"running"`, "status")
		wantAt(t, "GetHealth", health, `"neodesk"`, "backend")
		wantAt(t, "GetHealth", health, `2`, "peers_total")
		wantAt(t, "GetHealth", health, `"test"`, "version")

		// The statistics sit behind the metrics guard, which lets a call
		// from inside the process through.
		stats := c.GetServerStats(ctx)
		wantAt(t, "GetServerStats", stats, `true`, "success")
		wantAt(t, "GetServerStats", stats, `2`, "data", "peers_total")

		info := c.GetServerInfo(ctx)
		wantAt(t, "GetServerInfo", info, `"ok"`, "health", "status")
		wantAt(t, "GetServerInfo", info, `2`, "stats", "peers_total")
		wantAt(t, "GetServerInfo", info, `"neodesk"`, "backend")

		got, err := NewBackend(c, &fakeStore{}).GetStats(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wantJSON(t, "Backend.GetStats", got, `{"total":2,"online":0,"offline":2,"banned":0,"withNotes":0}`)
	})

	t.Run("peers", func(t *testing.T) {
		peers := c.GetAllPeers(ctx, false)
		if len(peers) != 2 {
			t.Fatalf("GetAllPeers = %s", toJSON(t, peers))
		}
		a := c.GetPeer(ctx, "PEERAAA1")
		for key, want := range map[string]string{
			"id": `"PEERAAA1"`, "hostname": `"host-a"`, "username": `"alice"`, "platform": `"Windows"`, "os": `"Windows"`,
			"note": `"n1"`, "tags": `["t1","t2"]`, "online": `false`, "no_signal": `false`, "banned": `false`,
			"last_online": `"2020-01-01T00:00:00Z"`, "status_tier": `"OFFLINE"`, "device_type": `"rustdesk"`, "banned_at": `null`, "uuid": `"uuid-a"`,
		} {
			wantAt(t, "GetPeer", a, want, key)
		}
		if got := c.GetPeer(ctx, "NOSUCH99"); got != nil {
			t.Errorf("GetPeer of an unknown id = %s", toJSON(t, got))
		}

		wantJSON(t, "UpdatePeer", c.UpdatePeer(ctx, "PEERAAA1", NewObject("note", "n2")), `{"success":true,"data":{"id":"PEERAAA1","status":"updated"}}`)
		wantAt(t, "GetPeer after UpdatePeer", c.GetPeer(ctx, "PEERAAA1"), `"n2"`, "note")
		wantJSON(t, "UpdatePeer without fields", c.UpdatePeer(ctx, "PEERAAA1", NewObject()), `{"success":false,"error":"No fields to update"}`)
		wantJSON(t, "GetLinkedPeers", c.GetLinkedPeers(ctx, "PEERAAA1"), `{"success":true,"data":{"linked":null,"peer_id":"PEERAAA1","total":0}}`)

		wantJSON(t, "SetPeerTags", c.SetPeerTags(ctx, "PEERAAA1", "x, y"), `{"success":true,"data":{"id":"PEERAAA1","status":"updated","tags":"x,y"}}`)
		tagged := c.GetPeersByTag(ctx, "y")
		if len(tagged) != 1 || tagged[0].Str("id") != "PEERAAA1" || toJSON(t, tagged[0].Get("tags")) != `["x","y"]` {
			t.Errorf("GetPeersByTag = %s", toJSON(t, tagged))
		}
		wantJSON(t, "GetPeersByTag without a match", c.GetPeersByTag(ctx, "none"), `[]`)

		wantJSON(t, "BanPeer", c.BanPeer(ctx, "PEERBBB2", "why"), `{"success":true,"data":{"id":"PEERBBB2","status":"banned"}}`)
		banned := c.GetPeer(ctx, "PEERBBB2")
		wantAt(t, "GetPeer after BanPeer", banned, `true`, "banned")
		wantAt(t, "GetPeer after BanPeer", banned, `"why"`, "ban_reason")
		// The audit entry names who acted (BUGS L91): the console's own key,
		// as the call names no account.
		wantAt(t, "GetAuditEvents", c.GetAuditEvents(ctx, 1.0), `"apikey:console-bridge"`, "data", "events", 0, "actor")
		wantAt(t, "GetAuditEvents", c.GetAuditEvents(ctx, 1.0), `"peer_banned"`, "data", "events", 0, "action")
		wantJSON(t, "UnbanPeer", c.UnbanPeer(ctx, "PEERBBB2"), `{"success":true,"data":{"id":"PEERBBB2","status":"unbanned"}}`)

		wantJSON(t, "ChangePeerID to a taken id", c.ChangePeerID(ctx, "PEERBBB2", "PEERAAA1"), `{"success":false,"error":"Device ID already exists"}`)
		wantJSON(t, "RestorePeer of an unknown id", c.RestorePeer(ctx, "NOSUCH99"), `{"success":false,"error":"peer not found"}`)

		wantAt(t, "DeletePeer", c.DeletePeer(ctx, "PEERBBB2", DeleteOptions{}), `"deleted"`, "data", "status")
		if got := c.GetAllPeers(ctx, false); len(got) != 1 {
			t.Errorf("GetAllPeers after a delete = %s", toJSON(t, got))
		}
		if got := c.GetAllPeers(ctx, true); len(got) != 2 {
			t.Errorf("GetAllPeers with deleted = %s", toJSON(t, got))
		}
		gone := c.GetPeerIncludingDeleted(ctx, "PEERBBB2")
		wantAt(t, "GetPeerIncludingDeleted", gone, `true`, "soft_deleted")
		wantAt(t, "GetPeerIncludingDeleted", gone, `true`, "disabled")
		if got := c.GetPeerIncludingDeleted(ctx, "NOSUCH99"); got != nil {
			t.Errorf("GetPeerIncludingDeleted of an unknown id = %s", toJSON(t, got))
		}
		wantAt(t, "RestorePeer", c.RestorePeer(ctx, "PEERBBB2"), `"restored"`, "data", "status")
		if got := c.GetAllPeers(ctx, false); len(got) != 2 {
			t.Errorf("GetAllPeers after the restore = %s", toJSON(t, got))
		}
	})

	t.Run("status", func(t *testing.T) {
		wantAt(t, "GetStatusSummary", c.GetStatusSummary(ctx), `0`, "data", "online")
		wantJSON(t, "GetOnlinePeers", c.GetOnlinePeers(ctx), `[]`)
		wantAt(t, "GetPeerStatus", c.GetPeerStatus(ctx, "PEERAAA1"), `false`, "data", "in_memory")
		wantJSON(t, "GetPeerStatus of an unknown id", c.GetPeerStatus(ctx, "NOSUCH99"), notFound404)
		wantJSON(t, "GetPeerTelemetry", c.GetPeerTelemetry(ctx, "PEERAAA1"), `{"success":true,"data":{"device_id":"PEERAAA1","schema":1,"snapshots":{}}}`)
		wantJSON(t, "GetPeerTelemetry of an unknown id", c.GetPeerTelemetry(ctx, "NOSUCH99"), notFound404)
		wantAt(t, "RefreshPeerHardware", c.RefreshPeerHardware(ctx, "PEERAAA1"), `true`, "data", "accepted")
		wantJSON(t, "QueuePeerTelemetryCommand", c.QueuePeerTelemetryCommand(ctx, "PEERAAA1", "nope", nil), `{"success":false,"error":"command_not_allowed"}`)
		wantJSON(t, "GetConnectionMode", c.GetConnectionMode(ctx, "PEERAAA1"),
			`{"success":true,"data":{"command":null,"controllable":false,"device_id":"PEERAAA1","policy":null,"support_agent":false}}`)
		wantJSON(t, "GetConnectionMode of an unknown id", c.GetConnectionMode(ctx, "NOSUCH99"), `{"success":false,"error":"peer_not_found","status":404}`)
		wantJSON(t, "SetConnectionMode", c.SetConnectionMode(ctx, "PEERAAA1", NewObject("mode", "incoming-only", "reason", "r")),
			`{"success":false,"error":"capability_required","status":409}`)
		wantAt(t, "GetPeerAvailability", c.GetPeerAvailability(ctx, "PEERAAA1", "2026-01-01", -60.0), `-60`, "data", "tz_offset")
		wantJSON(t, "GetPeerAvailability with a bad id", c.GetPeerAvailability(ctx, "bad id", nil, nil), `{"success":false,"error":"Invalid peer ID"}`)
		wantJSON(t, "GetPeerConnectionSessions", c.GetPeerConnectionSessions(ctx, "PEERAAA1", 5.0), `{"success":true,"data":{"count":0,"peer_id":"PEERAAA1","sessions":[]}}`)
	})

	t.Run("access policy and connect password", func(t *testing.T) {
		wantAt(t, "GetAccessPolicy", c.GetAccessPolicy(ctx, "PEERAAA1"), `false`, "data", "unattended_enabled")
		// The save names the signed-in account it acts for, not an address
		wantJSON(t, "SaveAccessPolicy", c.SaveAccessPolicy(ActingFor(ctx, "olga"), "PEERAAA1", NewObject("unattended_enabled", true)), `{"success":true,"data":{"success":true}}`)
		saved := c.GetAccessPolicy(ctx, "PEERAAA1")
		wantAt(t, "GetAccessPolicy after the save", saved, `true`, "data", "unattended_enabled")
		wantAt(t, "GetAccessPolicy after the save", saved, `"olga"`, "data", "updated_by")
		wantJSON(t, "SaveAccessPolicy with a bad time",
			c.SaveAccessPolicy(ctx, "PEERAAA1", NewObject("schedule_enabled", true, "schedule_start_time", "99:99")), badRequest400)
		wantJSON(t, "DeleteAccessPolicy", c.DeleteAccessPolicy(ctx, "PEERAAA1"), `{"success":true,"data":{"success":true}}`)
		wantJSON(t, "GetAccessPolicy with a bad id", c.GetAccessPolicy(ctx, "bad/id"), `{"success":false,"error":"Invalid peerId"}`)

		data, err := c.GetPeerConnectPassword(ctx, "PEERAAA1")
		e := AsError(err)
		if data != nil || e == nil || e.Message != "Request failed with status code 404" || e.Status() != 404 || toJSON(t, e.Data()) != `{"password_set":false}` {
			t.Errorf("GetPeerConnectPassword = %v, %+v", data, e)
		}
	})

	t.Run("blocklist and configuration", func(t *testing.T) {
		wantJSON(t, "GetBlocklist", c.GetBlocklist(ctx), `{"success":true,"data":{"count":0,"enabled":true,"entries":null}}`)
		wantJSON(t, "RemoveBlocklistEntry", c.RemoveBlocklistEntry(ctx, "10.9.8.7"), `{"success":false,"error":"Entry not found"}`)

		wantJSON(t, "GetConfig of an unset key", c.GetConfig(ctx, "k1"), `{"success":true,"data":{"key":"k1","value":""}}`)
		wantJSON(t, "SetConfig", c.SetConfig(ctx, "k1", "v"), `{"success":true,"data":{"key":"k1","status":"ok"}}`)
		wantJSON(t, "GetConfig", c.GetConfig(ctx, "k1"), `{"success":true,"data":{"key":"k1","value":"v"}}`)
		wantJSON(t, "GetConfig with a bad key", c.GetConfig(ctx, "bad key"), badRequest400)
		wantJSON(t, "SetConfig with a bad key", c.SetConfig(ctx, "bad key", "v"),
			`{"success":false,"error":"Invalid config key. Must be 1-64 alphanumeric characters, underscores, hyphens, or dots."}`)
	})

	t.Run("device tokens", func(t *testing.T) {
		wantJSON(t, "ListDeviceTokens", c.ListDeviceTokens(ctx, false), `{"success":true,"data":{"count":0,"tokens":null}}`)
		created := c.CreateDeviceToken(ctx, NewObject("name", "t", "max_uses", 1.0))
		wantAt(t, "CreateDeviceToken", created, `true`, "success")
		wantAt(t, "CreateDeviceToken", created, `"t"`, "data", "name")
		token, _ := Dig(created, "data", "token").(string)
		if len(token) < 20 {
			t.Errorf("CreateDeviceToken gave no token: %s", toJSON(t, created))
		}
		tokenID := jsString(Dig(created, "data", "id"))

		wantAt(t, "GetDeviceToken", c.GetDeviceToken(ctx, tokenID), `"pending"`, "data", "status")
		if c.GetDeviceToken(ctx, tokenID).Object("data").Has("token") {
			t.Error("GetDeviceToken gave the token itself")
		}
		wantJSON(t, "GetDeviceToken with a bad id", c.GetDeviceToken(ctx, "abc"), `{"success":true,"data":"Invalid token ID\n","status":400}`)
		wantAt(t, "UpdateDeviceToken", c.UpdateDeviceToken(ctx, tokenID, NewObject("name", "t2", "max_uses", 2.0, "note", "")), `"t2"`, "data", "name")
		wantAt(t, "BindTokenToPeer", c.BindTokenToPeer(ctx, tokenID, "PEERAAA1"), `"PEERAAA1"`, "data", "peer_id")
		wantJSON(t, "BindTokenToPeer with a bad peer id", c.BindTokenToPeer(ctx, tokenID, "bad id"), `{"success":false,"error":"Invalid peerId"}`)
		wantJSON(t, "BulkGenerateTokens of none", c.BulkGenerateTokens(ctx, NewObject("count", 0.0)), `{"success":true,"data":"Count must be between 1 and 100\n","status":400}`)
		wantAt(t, "BulkGenerateTokens", c.BulkGenerateTokens(ctx, NewObject("count", 2.0, "name_prefix", "bulk")), `2`, "data", "count")
		wantJSON(t, "RevokeDeviceToken", c.RevokeDeviceToken(ctx, tokenID), `{"success":true,"data":{"message":"Token revoked","success":true}}`)
		wantJSON(t, "RevokeDeviceToken of an unknown id", c.RevokeDeviceToken(ctx, "99999"), `{"success":true,"data":"Token not found\n","status":404}`)
		wantAt(t, "ListDeviceTokens without revoked", c.ListDeviceTokens(ctx, false), `2`, "data", "count")
		wantAt(t, "ListDeviceTokens with revoked", c.ListDeviceTokens(ctx, true), `3`, "data", "count")
	})

	t.Run("enrollment", func(t *testing.T) {
		wantAt(t, "GetEnrollmentMode", c.GetEnrollmentMode(ctx), `"open"`, "data", "mode")
		wantJSON(t, "SetEnrollmentMode with an unknown mode", c.SetEnrollmentMode(ctx, "bogus"), `{"success":true,"data":"Invalid mode (open, managed, locked)\n","status":400}`)
		wantAt(t, "SetEnrollmentMode", c.SetEnrollmentMode(ctx, "managed"), `"managed"`, "data", "mode")
		wantAt(t, "GetEnrollmentMode after the change", c.GetEnrollmentMode(ctx), `"managed"`, "data", "mode")

		wantJSON(t, "GetEnrollmentPending", c.GetEnrollmentPending(ctx), `{"success":true,"data":[],"count":0}`)
		// In managed mode a device that registers waits for approval.
		resp, err := c.Post(ctx, "/devices/register", Body(NewObject("device_id", "PENDING01", "hostname", "new-host", "platform", "Linux", "version", "1.0")))
		if err != nil {
			t.Fatalf("register a device: %v (%s)", err, resp.Text())
		}
		pending := c.GetEnrollmentPending(ctx)
		wantAt(t, "GetEnrollmentPending", pending, `1`, "count")
		wantAt(t, "GetEnrollmentPending", pending, `"PENDING01"`, "data", 0, "device_id")

		wantJSON(t, "GetEnrollmentHistory", c.GetEnrollmentHistory(ctx, nil), `{"success":true,"data":[],"count":0}`)
		wantJSON(t, "GetEnrollmentHistory with an unknown status", c.GetEnrollmentHistory(ctx, "bogus"),
			`{"success":false,"error":"Request failed with status code 400","data":[],"count":0}`)
		wantJSON(t, "ApproveEnrollment of an unknown device", c.ApproveEnrollment(ctx, "NOSUCH99", "n", "standard", ""), notFound404)
		wantAt(t, "ApproveEnrollment", c.ApproveEnrollment(ctx, "PENDING01", "Desk", nil, "a,b"), `true`, "data", "success")
		wantAt(t, "GetEnrollmentHistory after the approval", c.GetEnrollmentHistory(ctx, "approved"), `1`, "count")
		wantAt(t, "GetPeer of the approved device", c.GetPeer(ctx, "PENDING01"), `"Desk"`, "display_name")

		// An id that never waited for approval has nothing to reject or clear.
		wantJSON(t, "RejectEnrollment of an id that is not pending", c.RejectEnrollment(ctx, "NOSUCH99", false), notFound404)
		wantJSON(t, "ClearEnrollmentRejection of an id never rejected", c.ClearEnrollmentRejection(ctx, "NOSUCH99"), notFound404)
		wantAt(t, "SetEnrollmentMode back", c.SetEnrollmentMode(ctx, "open"), `true`, "data", "success")
	})

	t.Run("pairing codes", func(t *testing.T) {
		created := c.CreatePairingCode(ctx, "desk")
		wantAt(t, "CreatePairingCode", created, `true`, "success")
		wantAt(t, "CreatePairingCode", created, `true`, "data", "success")
		wantAt(t, "CreatePairingCode", created, `"desk"`, "data", "label")
		// The code names the host of the API address the console uses.
		wantAt(t, "CreatePairingCode", created, `"127.0.0.1"`, "data", "host")
		if code, _ := Dig(created, "data", "code").(string); len(code) != 6 {
			t.Errorf("CreatePairingCode gave no code: %s", toJSON(t, created))
		}
		codeID, _ := Dig(created, "data", "id").(string)

		list := c.ListPairingCodes(ctx)
		wantAt(t, "ListPairingCodes", list, `1`, "data", "count")
		wantAt(t, "ListPairingCodes", list, `"apikey:console-bridge"`, "data", "codes", 0, "created_by")
		wantJSON(t, "RevokePairingCode", c.RevokePairingCode(ctx, codeID), `{"success":true,"data":{"id":"`+codeID+`","success":true}}`)
		wantJSON(t, "RevokePairingCode of an unknown id", c.RevokePairingCode(ctx, "nosuch"),
			`{"success":false,"error":"Request failed with status code 404","status":404}`)

		other := New(srv.API.InternalHandler(), WithHost("api.example.org:21121"))
		wantAt(t, "CreatePairingCode with another Host", other.CreatePairingCode(ctx, ""), `"api.example.org"`, "data", "host")
	})

	t.Run("branding", func(t *testing.T) {
		branding := c.GetBranding(ctx)
		wantAt(t, "GetBranding", branding, `true`, "success")
		wantAt(t, "GetBranding", branding, `"NeoDesk"`, "data", "company_name")
		wantAt(t, "SaveBranding", c.SaveBranding(ctx, NewObject("company_name", "Acme")), `"Acme"`, "data", "branding", "company_name")
		wantAt(t, "GetBranding after the save", c.GetBranding(ctx), `"Acme"`, "data", "company_name")
		wantJSON(t, "SaveBranding with a text", c.SaveBranding(ctx, "not an object"), badRequest400)
	})

	t.Run("roles and permissions", func(t *testing.T) {
		roles := c.ListRoles(ctx)
		wantAt(t, "ListRoles", roles, `true`, "success")
		wantAt(t, "ListRoles", roles, `"super_admin"`, "data", "roles", 0, "name")
		wantAt(t, "GetRolePermissions", c.GetRolePermissions(ctx, "viewer"), `"viewer"`, "data", "role")
		wantJSON(t, "GetRolePermissions of an unknown role", c.GetRolePermissions(ctx, "bogus"), `{"success":false,"error":"Invalid role","status":400}`)
		wantJSON(t, "ListRolePermissionOverrides", c.ListRolePermissionOverrides(ctx, ""), `{"success":true,"data":{"overrides":[]}}`)
		wantJSON(t, "SetRolePermission", c.SetRolePermission(ctx, "viewer", "device.edit", true), `{"success":true,"data":{"status":"ok"}}`)
		wantJSON(t, "ListRolePermissionOverrides of a role", c.ListRolePermissionOverrides(ctx, "viewer"),
			`{"success":true,"data":{"overrides":[{"role":"viewer","permission":"device.edit","granted":true}]}}`)
		permissions, _ := Dig(c.GetRolePermissions(ctx, "viewer"), "data", "permissions").([]any)
		if !strings.Contains(toJSON(t, permissions), `"device.edit"`) {
			t.Errorf("the override is not in the role's permissions: %s", toJSON(t, permissions))
		}
		wantJSON(t, "SetRolePermission for admin", c.SetRolePermission(ctx, "admin", "device.edit", false), `{"success":false,"error":"Cannot override super admin permissions","status":400}`)
		wantJSON(t, "DeleteRolePermission", c.DeleteRolePermission(ctx, "viewer", "device.edit"), `{"success":true,"data":{"status":"ok"}}`)
		wantJSON(t, "ListRolePermissionOverrides after the delete", c.ListRolePermissionOverrides(ctx, "viewer"), `{"success":true,"data":{"overrides":[]}}`)
	})

	t.Run("help requests", func(t *testing.T) {
		wantJSON(t, "ListHelpRequests", c.ListHelpRequests(ctx, NewObject("status", "pending", "limit", 5.0)), `{"success":true,"data":[]}`)
		// The API server sends this error as JSON with a text content type.
		wantJSON(t, "AcknowledgeHelpRequest of an unknown id", c.AcknowledgeHelpRequest(ctx, "999"), `{"success":false,"error":"not found"}`)
		wantJSON(t, "ResolveHelpRequest of an unknown id", c.ResolveHelpRequest(ctx, "999"), `{"success":false,"error":"not found"}`)

		id, err := srv.DB.CreateHelpRequest(&db.HelpRequest{DeviceID: "PEERAAA1", Hostname: "host-a", Message: "help me", Status: db.HelpStatusPending})
		if err != nil {
			t.Fatalf("seed a help request: %v", err)
		}
		list := c.ListHelpRequests(ctx, NewObject("device_id", "PEERAAA1"))
		wantAt(t, "ListHelpRequests", list, `"help me"`, "data", 0, "message")
		acknowledged := c.AcknowledgeHelpRequest(ctx, jsString(float64(id)))
		wantAt(t, "AcknowledgeHelpRequest", acknowledged, `"acknowledged"`, "data", "status")
		// The API server records the console's API key as the handler.
		wantAt(t, "AcknowledgeHelpRequest", acknowledged, `"apikey:console-bridge"`, "data", "handled_by")
		wantAt(t, "ResolveHelpRequest", c.ResolveHelpRequest(ctx, jsString(float64(id))), `"resolved"`, "data", "status")
	})

	t.Run("directory and single sign-on settings", func(t *testing.T) {
		wantAt(t, "GetLDAPConfig", c.GetLDAPConfig(ctx), `false`, "data", "enabled")
		wantJSON(t, "SaveLDAPConfig without a host", c.SaveLDAPConfig(ctx, NewObject("enabled", true)), badRequest400)
		// The test refuses settings it can't use with a reason (L353)
		wantJSON(t, "TestLDAPConnection without a host", c.TestLDAPConnection(ctx, NewObject()), `{"success":false,"error":"Enter the directory's host name or address."}`)
		wantAt(t, "GetOIDCConfig", c.GetOIDCConfig(ctx), `false`, "data", "enabled")
		wantJSON(t, "SaveOIDCConfig without an issuer", c.SaveOIDCConfig(ctx, NewObject("enabled", true)), badRequest400)
		wantJSON(t, "TestOIDCDiscovery without an issuer", c.TestOIDCDiscovery(ctx, NewObject()), badRequest400)
		wantJSON(t, "GetOIDCStatus", c.GetOIDCStatus(ctx), `{"success":true,"data":{"enabled":false}}`)
		wantJSON(t, "ExchangeOIDCCode", c.ExchangeOIDCCode(ctx, "x"), `{"success":false,"error":"Request failed with status code 401"}`)
		wantJSON(t, "StartOIDCAuthorize", c.StartOIDCAuthorize(ctx, "/devices"), `{"success":false,"error":"OIDC is not enabled"}`)
		if got := c.ProxyOIDCCallback(ctx, nil); got.Status < 300 || got.Status == 502 {
			t.Errorf("ProxyOIDCCallback without OIDC = %+v", got)
		}
	})

	t.Run("strategies", func(t *testing.T) {
		wantJSON(t, "AssignStrategy without a target", c.AssignStrategy(ctx, NewObject()), `{"success":false,"error":"at least one target is required"}`)
		wantJSON(t, "GetStrategy of an unknown id", c.GetStrategy(ctx, "nosuch"), notFound404)
		wantJSON(t, "DeleteStrategy of an unknown id", c.DeleteStrategy(ctx, "nosuch"), `{"success":false,"error":"Strategy not found"}`)
		wantJSON(t, "SetStrategyStatus of an unknown id", c.SetStrategyStatus(ctx, "nosuch", true), `{"success":false,"error":"strategy not found"}`)
		wantAt(t, "ListProDevices", c.ListProDevices(ctx, NewObject("pageSize", 2.0)), `true`, "success")
	})

	t.Run("remote targets", func(t *testing.T) {
		wantJSON(t, "GetAllRemoteTargets", c.GetAllRemoteTargets(ctx, "", false), `[]`)
		if got := c.GetRemoteTarget(ctx, "rt_nosuch0000"); got != nil {
			t.Errorf("GetRemoteTarget of an unknown id = %s", toJSON(t, got))
		}
		wantJSON(t, "CreateRemoteTarget without a protocol", c.CreateRemoteTarget(ctx, NewObject("name", "x")), `{"success":false,"error":"protocol must be rdp or vnc"}`)
		wantJSON(t, "TestRemoteTarget without a name", c.TestRemoteTarget(ctx, NewObject()),
			`{"success":false,"error":"name is required and must be at most 160 characters"}`)
		const missing = `{"success":false,"error":"remote target not found"}`
		wantJSON(t, "UpdateRemoteTarget", c.UpdateRemoteTarget(ctx, "rt_nosuch0000", NewObject("name", "y")), missing)
		wantJSON(t, "DeleteRemoteTarget", c.DeleteRemoteTarget(ctx, "rt_nosuch0000"), missing)
		wantJSON(t, "GetRemoteTargetCredentialStatus", c.GetRemoteTargetCredentialStatus(ctx, "rt_nosuch0000"), missing)
		wantJSON(t, "SetRemoteTargetCredentials", c.SetRemoteTargetCredentials(ctx, "rt_nosuch0000", NewObject("username", "u", "password", "p")),
			`{"success":false,"error":"remote target credential vault is not configured"}`)
		wantJSON(t, "ClearRemoteTargetCredentials", c.ClearRemoteTargetCredentials(ctx, "rt_nosuch0000"), missing)
		// L83: no vault key and no guacd in the test server
		wantJSON(t, "GetRemoteTargetReadiness", c.GetRemoteTargetReadiness(ctx), `{"success":true,"data":{"guacd":false,"vault":false}}`)
		wantJSON(t, "AcceptRemoteTargetCertificate", c.AcceptRemoteTargetCertificate(ctx, "rt_nosuch0000", "ab"), missing)

		created := c.CreateRemoteTarget(ctx, NewObject("name", "Server", "protocol", "rdp", "host", "10.0.0.9", "port", 3389.0))
		wantAt(t, "CreateRemoteTarget", created, `true`, "success")
		targetID, _ := Dig(created, "data", "id").(string)
		target := c.GetRemoteTarget(ctx, targetID)
		for key, want := range map[string]string{
			"hostname": `"Server"`, "device_type": `"rdp"`, "remote_target": `true`, "online": `false`, "status": `"OFFLINE"`,
			"note": `"10.0.0.9:3389"`, "soft_deleted": `false`,
		} {
			wantAt(t, "GetRemoteTarget", target, want, key)
		}
		if got := c.GetAllRemoteTargets(ctx, "", false); len(got) != 1 || got[0].Str("id") != targetID {
			t.Errorf("GetAllRemoteTargets = %s", toJSON(t, got))
		}
		// The device layer finds a target by its id prefix.
		if got := NewBackend(c, &fakeStore{}).GetDeviceByID(ctx, targetID, false); got == nil || !got.Bool("remote_target") {
			t.Errorf("Backend.GetDeviceByID of a target = %s", toJSON(t, got))
		}
		wantAt(t, "DeleteRemoteTarget", c.DeleteRemoteTarget(ctx, targetID), `"deleted"`, "data", "status")
	})

	t.Run("mesh and device protocol", func(t *testing.T) {
		wantAt(t, "GetMeshStatus", c.GetMeshStatus(ctx), `true`, "data", "enabled")
		wantAt(t, "GetCDAPStatus", c.GetCDAPStatus(ctx), `true`, "data", "enabled")
		wantJSON(t, "GetCDAPDevices", c.GetCDAPDevices(ctx), `{"success":true,"data":{"devices":[],"total":0}}`)
		wantJSON(t, "GetCDAPDeviceInfo", c.GetCDAPDeviceInfo(ctx, "PEERAAA1"), notFound404)
		wantJSON(t, "GetCDAPDeviceManifest", c.GetCDAPDeviceManifest(ctx, "PEERAAA1"), notFound404)
		wantJSON(t, "GetCDAPDeviceState", c.GetCDAPDeviceState(ctx, "PEERAAA1"), notFound404)
		wantJSON(t, "SendCDAPCommand", c.SendCDAPCommand(ctx, "PEERAAA1", "w", "set", 1.0, ""), notFound404)
		wantJSON(t, "GetCDAPAlerts", c.GetCDAPAlerts(ctx, nil), `{"success":true,"data":{"alerts":[],"total":0}}`)
		wantJSON(t, "GetCDAPAlerts of a device", c.GetCDAPAlerts(ctx, "PEERAAA1"), `{"success":true,"data":{"alerts":[],"total":0}}`)
	})

	t.Run("client audit", func(t *testing.T) {
		wantJSON(t, "GetClientAuditConnections", c.GetClientAuditConnections(ctx, NewObject("limit", 5.0)), `{"data":[],"total":0}`)
		wantJSON(t, "GetClientAuditFiles", c.GetClientAuditFiles(ctx, nil), `{"data":[],"total":0}`)
		wantJSON(t, "GetClientAuditAlarms", c.GetClientAuditAlarms(ctx, NewObject("limit", 5.0)), `{"data":[],"total":0}`)
	})

	t.Run("direct calls", func(t *testing.T) {
		// A path the API server does not have.
		resp, err := c.Get(ctx, "/no-such-path")
		if e := AsError(err); resp == nil || e == nil || e.Status() != 404 || toJSON(t, e.Data()) != `{"error":"not found"}` {
			t.Errorf("GET of a path that does not exist: %+v, %+v", resp, e)
		}
		// A known path with another method is the same 404.
		_, err = c.Put(ctx, "/help/requests", Body(NewObject("device_id", "PEERAAA1")))
		if e := AsError(err); e == nil || e.Status() != 404 || toJSON(t, e.Data()) != `{"error":"not found"}` {
			t.Errorf("PUT /help/requests: %+v", e)
		}
		// An error in plain words stays text.
		_, err = c.Get(ctx, "/tokens/abc")
		if e := AsError(err); e == nil || e.Status() != 400 || e.Data() != "Invalid token ID\n" {
			t.Errorf("GET /tokens/abc: %+v, data %#v", e, e.Data())
		}

		resp, err = c.Post(ctx, "/org", Body(NewObject("name", "Org One", "slug", "org-one")))
		if err != nil || resp.Status != 201 {
			t.Fatalf("POST /org: %+v, %v", resp, err)
		}
		orgID, _ := Dig(resp.Data(), "id").(string)
		resp, err = c.Get(ctx, "/org")
		if err != nil || toJSON(t, Dig(resp.Data(), "organizations", 0, "id")) != `"`+orgID+`"` {
			t.Errorf("GET /org: %s, %v", resp.Text(), err)
		}
		// A refusal of the API server as JSON (BUGS L398: it was JSON text
		// with a text content type)
		resp, err = c.Post(ctx, "/org", Body(NewObject("name", "", "slug", "x")))
		if e := AsError(err); e == nil || resp.Header.Get("Content-Type") != "application/json" || toJSON(t, e.Data()) != `{"error":"name is required"}` {
			t.Errorf("POST /org without a name: %+v (%s)", e, resp.Header.Get("Content-Type"))
		}

		// An escaped dot segment is an organization id, not a way to another
		// route: this must not answer with the user list of GET /api/users.
		resp, err = c.Get(ctx, "/org/%2e%2e/users")
		if _, isList := resp.Data().([]any); isList || resp.Status == 200 && Dig(resp.Data(), "users") == nil {
			t.Errorf("GET /org/%%2e%%2e/users reached another route: %d %s (%v)", resp.Status, resp.Text(), err)
		}

		resp, err = c.Get(ctx, "/peers", Query("limit", 1.0))
		if err != nil || toJSON(t, Dig(resp.Data(), "total")) != `3` {
			t.Errorf("GET /peers?limit=1: %s, %v", resp.Text(), err)
		}
	})

	t.Run("events", func(t *testing.T) {
		evCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		frames, err := c.Events(evCtx, "")
		if err != nil {
			t.Fatal(err)
		}
		wantAt(t, "ChangePeerID", c.ChangePeerID(ctx, "PEERBBB2", "PEERBBB9"), `"changed"`, "data", "status")
		frame := nextFrame(t, frames)
		if frame.Str("type") != "peer_id_changed" || toJSON(t, frame.Get("data")) != `{"new_id":"PEERBBB9","old_id":"PEERBBB2","source":"panel"}` {
			t.Errorf("frame = %s", toJSON(t, frame))
		}
	})
}

// TestSignInAgainstAPIServer runs the sign-in calls against the real
// handlers, including the limit they share.
func TestSignInAgainstAPIServer(t *testing.T) {
	c, _ := realClient(t)
	c.signInCap = time.Minute // hashing a password can take seconds under the race detector
	ctx := context.Background()

	if !c.CheckGoServerHealth(ctx) {
		t.Error("CheckGoServerHealth = false")
	}
	wantJSON(t, "GetGoSSOStatus", c.GetGoSSOStatus(ctx), `{"ldap":false,"oidc":false,"any":false}`)

	// A good sign-in.
	good := c.TryGoServerAuth(ctx, apitest.AdminUser, apitest.AdminPassword)
	wantAt(t, "TryGoServerAuth", good, `"admin"`, "role")
	// Call 2: a directory check, refused because there is no directory.
	if c.TryLDAPVerifyOnGo(ctx, apitest.AdminUser, apitest.AdminPassword) {
		t.Error("TryLDAPVerifyOnGo = true without a directory")
	}
	// Calls 3 to 5: wrong passwords, for different names.
	if got := c.TryGoServerAuth(ctx, "user-three", "wrong"); got != nil {
		t.Errorf("TryGoServerAuth with a wrong password = %s", toJSON(t, got))
	}
	rejected := c.AuthenticateViaGo(ctx, "user-four", "wrong")
	wantAt(t, "AuthenticateViaGo with a wrong password", rejected, `true`, "rejected")
	wantAt(t, "AuthenticateViaGo with a wrong password", rejected, `401`, "status")
	full := c.AuthenticateViaGo(ctx, apitest.AdminUser, apitest.AdminPassword)
	if token, _ := Dig(full, "token").(string); token == "" {
		t.Errorf("AuthenticateViaGo = %s, want a token", toJSON(t, full))
	}

	// Only failed sign-ins count (L352): the two good ones did not, the
	// directory check and the two wrong passwords did. Two more wrong ones
	// make five, and then the address is over the limit, also with the
	// right password and for a name not tried before.
	for _, name := range []string{"user-six", "user-seven"} {
		if got := c.AuthenticateViaGo(ctx, name, "wrong"); Dig(got, "rateLimited") == true {
			t.Errorf("AuthenticateViaGo for %s under the limit = %s", name, toJSON(t, got))
		}
	}
	limited := c.AuthenticateViaGo(ctx, "user-eight", "wrong")
	wantAt(t, "AuthenticateViaGo over the limit", limited, `true`, "rateLimited")
	wantJSON(t, "TryGoServerAuth over the limit", c.TryGoServerAuth(ctx, apitest.AdminUser, apitest.AdminPassword), `{"rate_limited":true}`)
	limitedTOTP := c.VerifyTOTPViaGo(ctx, "partial", "123456")
	wantAt(t, "VerifyTOTPViaGo over the limit", limitedTOTP, `true`, "rateLimited")
}

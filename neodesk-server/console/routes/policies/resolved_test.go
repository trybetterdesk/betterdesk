package policies_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/neodeskapp/neodesk/neodesk-server/console/routes/internal/routetest"
)

const stored = `{"connection":{"mode":"attended"},"features":{},"security":{},"network":{"ip_allowlist":["10.0.0.0/8"]},"update":{}}`

// decode reads an answer as JSON values, so that groups compare as values.
func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("answer is no JSON object: %v: %s", err, body)
	}
	return out
}

// none is a field without a stored value and without a server setting.
const none = `{"value":null,"source":"none"}`

// TestResolvedPoliciesSayWhatIsInForce: each group says whether anything
// is stored, who applies it (the server for network, the device for the
// rest, which the full desktop app doesn't read yet), which of its
// settings the receiver app applies (session approval and removing the
// app) and when; each field its stored
// value and where the value in force comes from. block_direct_p2p is the
// one field with a server-wide setting: the server's connection strategy
// as the running server reports it.
func TestResolvedPoliciesSayWhatIsInForce(t *testing.T) {
	for _, relayOnly := range []bool{true, false} {
		api := routetest.NewAPI()
		api.On("GET /api/org/org-1/policy", 200, stored)
		relay := "false"
		if relayOnly {
			relay = "true"
		}
		api.On("GET /api/health/detail", 200, `{"status":"ok","connection":{"always_use_relay":`+relay+`}}`)
		got := routetest.New(t, routetest.Options{API: api}).As("admin").Do("GET", "/api/panel/policies/org-1/resolved", "")
		if got.Status != 200 {
			t.Fatalf("resolved: %d %s", got.Status, got.Body)
		}
		answer := decode(t, got.Body)
		want := decode(t, `{
			"connection":{"set":true,"applied_by":"device","device_app_applies":false,"receiver_applies":["mode"],"timing":"device_next_check","fields":{
				"idle_lock_timeout":`+none+`,"max_session_duration":`+none+`,"mode":{"value":"attended","source":"organization"},"wallpaper":`+none+`}},
			"features":{"set":false,"applied_by":"device","device_app_applies":false,"receiver_applies":[],"timing":"device_next_check","fields":{
				"allow_audio":`+none+`,"allow_clipboard":`+none+`,"allow_file_transfer":`+none+`,"allow_recording":`+none+`}},
			"security":{"set":false,"applied_by":"device","device_app_applies":false,"receiver_applies":["allow_uninstall","allowed_operators"],"timing":"device_next_check","fields":{
				"allow_uninstall":`+none+`,"allowed_operators":`+none+`,"password_max_age_days":`+none+`,"password_min_length":`+none+`,"password_require_special":`+none+`,"require_2fa":`+none+`}},
			"network":{"set":true,"applied_by":"server","device_app_applies":false,"receiver_applies":[],"timing":"server_minute","fields":{
				"allowed_relay_servers":`+none+`,
				"block_direct_p2p":{"value":null,"source":"server","server_value":`+relay+`,
					"server_setting":{"label_key":"settings.connection_mode_title","href":"/settings#connection-mode-section"}},
				"ip_allowlist":{"value":["10.0.0.0/8"],"source":"organization"}}},
			"update":{"set":false,"applied_by":"device","device_app_applies":false,"receiver_applies":[],"timing":"device_next_check","fields":{
				"auto_update":`+none+`,"channel":`+none+`}}
		}`)
		if !reflect.DeepEqual(answer, want) {
			t.Errorf("relay only %v:\n got  %s", relayOnly, got.Body)
		}
	}
}

// TestResolvedBlockDirectSetHereKeepsTheServerValue: an organization's own
// block_direct_p2p is the source, and the server's value is still named,
// since a server that relays everything relays this organization too.
func TestResolvedBlockDirectSetHereKeepsTheServerValue(t *testing.T) {
	api := routetest.NewAPI()
	api.On("GET /api/org/org-1/policy", 200, `{"network":{"block_direct_p2p":false}}`)
	api.On("GET /api/health/detail", 200, `{"connection":{"always_use_relay":true}}`)
	got := routetest.New(t, routetest.Options{API: api}).As("admin").Do("GET", "/api/panel/policies/org-1/resolved", "")
	network, _ := decode(t, got.Body)["network"].(map[string]any)
	fields, _ := network["fields"].(map[string]any)
	want := decode(t, `{"value":false,"source":"organization","server_value":true,
		"server_setting":{"label_key":"settings.connection_mode_title","href":"/settings#connection-mode-section"}}`)
	if got.Status != 200 || !reflect.DeepEqual(fields["block_direct_p2p"], want) || network["set"] != true {
		t.Errorf("resolved: %d %s", got.Status, got.Body)
	}
}

// TestResolvedPoliciesGuardsAndFailures: the same guards as reading the
// policies; an organization id that cannot go into a path is refused
// before any call; an API server without policy routes (404) means
// nothing is stored, any other failure is passed on.
func TestResolvedPoliciesGuardsAndFailures(t *testing.T) {
	api := routetest.NewAPI()
	api.On("GET /api/org/gone/policy", 404, `{"error":"not found"}`)
	api.On("GET /api/org/broken/policy", 500, `{"error":"boom"}`)
	api.On("GET /api/org/org-1/policy", 200, `{}`)
	w := routetest.New(t, routetest.Options{API: api})
	if got := w.SignedOut().Do("GET", "/api/panel/policies/org-1/resolved", ""); got.Status != 401 {
		t.Errorf("signed out: %d %s", got.Status, got.Body)
	}
	if got := w.As("operator").Do("GET", "/api/panel/policies/org-1/resolved", ""); got.Status != 403 {
		t.Errorf("operator: %d %s", got.Status, got.Body)
	}
	if calls := api.Calls(); calls != nil {
		t.Errorf("the API server was asked for accounts that may not: %v", calls)
	}
	if got := w.As("server_admin").Do("GET", "/api/panel/policies/org-1/resolved", ""); got.Status != 200 {
		t.Errorf("server_admin reads like GET /api/panel/policies/{orgId}: %d %s", got.Status, got.Body)
	}
	admin := w.As("admin")
	if got := admin.Do("GET", "/api/panel/policies/bad%20id/resolved", ""); got.Status != 400 || got.Body != `{"error":"Invalid orgId"}` {
		t.Errorf("bad id: %d %s", got.Status, got.Body)
	}
	got := admin.Do("GET", "/api/panel/policies/gone/resolved", "")
	network, _ := decode(t, got.Body)["network"].(map[string]any)
	if got.Status != 200 || network["set"] != false {
		t.Errorf("no policy routes: %d %s", got.Status, got.Body)
	}
	if got := admin.Do("GET", "/api/panel/policies/broken/resolved", ""); got.Status != 500 || got.Body != `{"error":"boom"}` {
		t.Errorf("a failure: %d %s", got.Status, got.Body)
	}
}

// TestClearingAPolicyGroup: DELETE clears one group by storing an empty
// one, with the guards of the write.
func TestClearingAPolicyGroup(t *testing.T) {
	api := routetest.NewAPI()
	api.On("PUT /api/org/org-1/policy/network", 200, `{"success":true}`)
	w := routetest.New(t, routetest.Options{API: api})
	if got := w.SignedOut().Do("DELETE", "/api/panel/policies/org-1/network", ""); got.Status != 401 {
		t.Errorf("signed out: %d %s", got.Status, got.Body)
	}
	if got := w.As("operator").Do("DELETE", "/api/panel/policies/org-1/network", ""); got.Status != 403 {
		t.Errorf("operator: %d %s", got.Status, got.Body)
	}
	if got := w.As("server_admin").Do("DELETE", "/api/panel/policies/org-1/network", ""); got.Status != 403 || got.Body != `{"success":false,"error":"Permission denied: org.edit"}` {
		t.Errorf("server_admin: %d %s", got.Status, got.Body)
	}
	if calls := api.Calls(); calls != nil {
		t.Errorf("the API server was asked for accounts that may not: %v", calls)
	}
	admin := w.As("admin")
	if got := admin.Do("DELETE", "/api/panel/policies/org-1/network", ""); got.Status != 200 || got.Body != `{"success":true}` {
		t.Errorf("clear: %d %s", got.Status, got.Body)
	}
	if calls := strings.Join(api.Calls(), "\n"); calls != "PUT /api/org/org-1/policy/network {}" {
		t.Errorf("calls: %s", calls)
	}
	if got := admin.Do("DELETE", "/api/panel/policies/bad%20id/network", ""); got.Status != 400 || got.Body != `{"error":"Invalid orgId"}` {
		t.Errorf("bad id: %d %s", got.Status, got.Body)
	}
	if got := admin.Do("DELETE", "/api/panel/policies/org-1/bogus", ""); got.Status != 404 {
		t.Errorf("unknown group: %d %s", got.Status, got.Body)
	}
	if calls := api.Calls(); calls != nil {
		t.Errorf("refused clears reached the API server: %v", calls)
	}
}

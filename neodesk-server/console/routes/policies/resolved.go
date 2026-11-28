package policies

import (
	"context"
	"net/http"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/api"
	"github.com/neodeskapp/neodesk/neodesk-server/console/goapi"
	"github.com/neodeskapp/neodesk/neodesk-server/console/goapipath"
	"github.com/neodeskapp/neodesk/neodesk-server/console/serverinfo"
)

// desktopAppReadsPolicies says whether the full NeoDesk desktop app
// applies the groups it gets at GET /api/nd/device-policy (connection,
// features, security, update). No release of it reads them yet; set it to
// true with the release that does.
const desktopAppReadsPolicies = false

// receiverApplies are the settings, per group, that the receiver app (the
// NeoDesk app installed with the receiver MSI) applies from GET
// /api/nd/device-policy: session approval and whether people at the
// computer can remove the app since neodesk-client#28, and the accounts
// that may connect without asking (A279), which the server's caller check
// applies too. It checks every five minutes. It applies no other setting.
var receiverApplies = map[string][]string{
	"connection": {"mode"},
	"security":   {"allow_uninstall", "allowed_operators"},
}

// serverGroups are the groups the server applies itself (package policy,
// signal routing, with a cache of a minute): the device app has nothing
// to do for them.
var serverGroups = map[string]bool{"network": true}

// serverSetting is a server-wide setting a policy field falls back to: the
// translation key of its name and where in the console it is set.
type serverSetting struct {
	LabelKey string `json:"label_key"`
	Href     string `json:"href"`
}

// connectionStrategy is Settings > General, connection strategy (the
// section connection-mode-section of web-ui/src/lib/settings/search-index.ts).
var connectionStrategy = serverSetting{LabelKey: "settings.connection_mode_title", Href: "/settings#connection-mode-section"}

// resolved answers GET /api/panel/policies/{orgId}/resolved: for each
// policy group whether anything is stored, who applies it and when, and
// for each of its settings (api.PolicyFields) the stored value and where
// the value in force comes from:
//
//	{<group>: {set, applied_by: "server"|"device", device_app_applies,
//	  receiver_applies: [<field>...],
//	  timing: "server_minute"|"device_next_check",
//	  fields: {<field>: {value, source: "organization"|"server"|"none",
//	    server_value?, server_setting?: {label_key, href}}}}}
//
// device_app_applies is whether the full desktop app applies the group;
// receiver_applies names the group's settings the receiver app applies
// (receiverApplies), [] for none. "none" is a setting without a rule:
// each device keeps its own. Only
// block_direct_p2p has a server-wide setting, the connection strategy:
// with "Always through the relay" no connection goes direct.
func (h *handlers) resolved(w http.ResponseWriter, r *http.Request) {
	path, err := policyPath(r, "")
	if err != nil {
		refuse(w, r, err)
		return
	}
	stored := goapi.NewObject()
	resp, err := h.api.Request(r.Context(), http.MethodGet, path)
	if err == nil {
		if o, isObject := resp.Data().(*goapi.Object); isObject {
			stored = o
		}
	} else if status, data := goapipath.FailureOf(err, "Go server unreachable"); status != http.StatusNotFound {
		goapipath.WriteJSON(w, r, status, data)
		return
	}
	relayOnly := h.relayOnly(r.Context())
	out := goapi.NewObject()
	for _, group := range api.PolicyFields() {
		values, _ := stored.Get(group.Group).(*goapi.Object)
		appliedBy, timing, appApplies := "device", "device_next_check", desktopAppReadsPolicies
		receiver := []any{}
		for _, name := range receiverApplies[group.Group] {
			receiver = append(receiver, name)
		}
		if serverGroups[group.Group] {
			appliedBy, timing, appApplies, receiver = "server", "server_minute", false, []any{}
		}
		fields := goapi.NewObject()
		for _, name := range group.Fields {
			field := goapi.NewObject("value", nil, "source", "none")
			if values.Has(name) {
				field.Set("value", values.Get(name)).Set("source", "organization")
			}
			if group.Group == "network" && name == "block_direct_p2p" {
				if !values.Has(name) {
					field.Set("source", "server")
				}
				field.Set("server_value", relayOnly).Set("server_setting", connectionStrategy)
			}
			fields.Set(name, field)
		}
		out.Set(group.Group, goapi.NewObject(
			"set", values.Len() > 0,
			"applied_by", appliedBy,
			"device_app_applies", appApplies,
			"receiver_applies", receiver,
			"timing", timing,
			"fields", fields,
		))
	}
	goapipath.WriteJSON(w, r, http.StatusOK, out)
}

// relayOnly is the server's connection strategy as true for "Always
// through the relay": what the running server reports, else the saved
// setting, else nil when neither can be read.
func (h *handlers) relayOnly(ctx context.Context) any {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if always, isBool := goapi.Dig(h.api.GetHealth(ctx), "connection", "always_use_relay").(bool); isBool {
		return always
	}
	if h.info == nil {
		return nil
	}
	saved, err := h.info.GetConnectionMode(ctx)
	if err != nil {
		return nil
	}
	return saved.Mode == serverinfo.ModeRelayOnly
}

// clear answers DELETE /api/panel/policies/{orgId}/{category}: the group
// is stored empty, so none of its settings has a rule any more.
func (h *handlers) clear(suffix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path, err := policyPath(r, suffix)
		if err != nil {
			refuse(w, r, err)
			return
		}
		h.proxy(w, r, http.MethodPut, path, false, goapipath.Body(goapi.NewObject()))
	}
}

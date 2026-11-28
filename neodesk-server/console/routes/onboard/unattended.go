package onboard

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/auth"
	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/onboard"
	"github.com/neodeskapp/neodesk/neodesk-server/console/session"
	"github.com/neodeskapp/neodesk/neodesk-server/policy/unattended"
)

// The audit actions of unattended access (UNATTENDED-CONTRACT.md).
const (
	auditUnattendedStarted = "unattended_session_started"
	auditUnattendedEnded   = "unattended_session_ended"
	auditUnattendedRefused = "unattended_caller_refused"
)

// unattendedAnswer is POST /api/nd/unattended/caller when the server
// vouches for the caller.
type unattendedAnswer struct {
	Success        bool   `json:"success"`
	Vouched        bool   `json:"vouched"`
	DeviceID       string `json:"device_id"`
	Session        string `json:"session"`
	Helper         string `json:"helper"`
	HelperUsername string `json:"helper_username"`
	// HelperAvatar is the account's console picture as a data URL, left
	// out when it has none or it does not fit
	HelperAvatar string `json:"helper_avatar,omitempty"`
	Via          string `json:"via"`
}

// unattendedCaller answers POST /api/nd/unattended/caller with the body
// {session}: a receiver got a relayed connection without a password and
// asks whether the server vouches that a signed-in account opened it and
// may connect now without someone at the computer clicking Allow (A279).
// The device token and the device it names were checked in front. The
// server vouches only over HTTPS, for the live relay session to the
// token's device that met on the relay less than a minute ago and was not
// vouched for before, opened by the browser viewer of a console session or
// a desktop app signed in to NeoDesk, of an enabled account that has
// Connect to devices and sees the device, when the rule allows it now. It
// writes the audit entry before it answers. Anything else is 409
// not_vouched with the reason, and the receiver asks for Allow as before.
// Wire format and the table of checks: PROTOCOL.md.
func (h *handlers) unattendedCaller(w http.ResponseWriter, r *http.Request) {
	device := kit.Device(r).DeviceID
	var body struct {
		Session string `json:"session"`
	}
	if err := kit.Bind(r, &body); err != nil {
		appFail(w, r, http.StatusBadRequest, "invalid_body", "")
		return
	}
	relaySession := strings.TrimSpace(body.Session)
	if relaySession == "" || len(relaySession) > 128 || device == "" {
		appFail(w, r, http.StatusBadRequest, "invalid_body", "")
		return
	}
	notVouched := func(reason string) {
		kit.JSON(w, r, http.StatusConflict, refusal{Error: "not_vouched", Reason: reason})
	}
	// On plain HTTP someone on the way could fake this answer (A273)
	if !kit.Secure(r) {
		notVouched("not_https")
		return
	}
	ctx := r.Context()
	pair, refused, account, err := h.sessions.UnattendedCaller(ctx, device, relaySession)
	if err != nil {
		h.log.Error("Unattended caller:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	who := func(username string) string {
		name := h.personName(ctx, account, username)
		if username == "" || name == username {
			return name
		}
		return name + " (" + username + ")"
	}
	// refuse writes the refusal of a known account to the audit log
	// before it answers; actor is 0 for an account without a row
	refuse := func(reason string, actor int64, username string) {
		if h.d.Audit != nil && account > 0 {
			details := unattendedDetails(device, "refused", "helper="+who(username), "reason="+reason, "relay_session="+relaySession)
			if err := h.d.Audit.WriteAbout(ctx, actor, account, auditUnattendedRefused, details, kit.ClientIP(r)); err != nil {
				h.log.Warn("Audit entry "+auditUnattendedRefused+" failed:", err)
			}
		}
		notVouched(reason)
	}
	if refused != "" {
		if refused == "session_not_open" || account <= 0 || h.d.Authn == nil {
			notVouched(refused)
			return
		}
		acct, err := h.d.Authn.UserByID(ctx, account)
		if err != nil || acct == nil {
			refuse(refused, 0, "")
			return
		}
		refuse(refused, account, acct.Username)
		return
	}
	if h.d.Authn == nil || h.d.Access == nil {
		notVouched("no_permission")
		return
	}
	acct, err := h.d.Authn.UserByID(ctx, account)
	if err != nil {
		h.log.Error("Unattended caller account:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	if acct == nil {
		refuse("no_permission", 0, "")
		return
	}
	if acct.Disabled.True() {
		refuse("no_permission", account, acct.Username)
		return
	}
	role := acct.Role.String
	may, err := h.d.Access.RoleHasEffectivePermission(ctx, role, auth.PermDeviceConnect)
	if err != nil {
		h.log.Error("Unattended caller permission:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	if !may {
		refuse("no_permission", account, acct.Username)
		return
	}
	if h.d.DeviceGroups == nil || h.d.Backend == nil {
		// Without the scope check nobody is vouched for
		refuse("no_permission", account, acct.Username)
		return
	}
	dev := h.d.Backend.GetDeviceByID(ctx, device, false)
	inScope, err := h.d.DeviceGroups.UserCanAccessDevice(ctx, &session.User{ID: account, Username: acct.Username, Role: role}, dev)
	if err != nil {
		h.log.Error("Unattended caller scope:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	if !inScope {
		refuse("no_permission", account, acct.Username)
		return
	}
	now := h.now()
	if decision := unattended.Evaluate(unattended.Input{
		Mode: pair.Mode, OrgOperators: pair.OrgOperators, Access: pair.Access, Caller: acct.Username, Now: now,
	}); decision != unattended.Allow {
		refuse(decision, account, acct.Username)
		return
	}
	name := h.personName(ctx, account, acct.Username)
	if h.d.Audit == nil {
		// No proof goes out that the log does not hold
		appFail(w, r, http.StatusInternalServerError, "audit_failed", "")
		return
	}
	details := unattendedDetails(device, "started", "helper="+who(acct.Username), "via="+pair.Via, "relay_session="+relaySession)
	if err := h.d.Audit.WriteAbout(ctx, account, account, auditUnattendedStarted, details, kit.ClientIP(r)); err != nil {
		h.log.Error("Unattended caller audit:", err)
		appFail(w, r, http.StatusInternalServerError, "audit_failed", "")
		return
	}
	h.d.Unattended.Add(onboard.Vouched{
		Session: relaySession, DeviceID: device, Account: account, Actor: account,
		Helper: who(acct.Username), Via: pair.Via, Since: now,
	})
	kit.JSON(w, r, http.StatusOK, unattendedAnswer{
		Success: true, Vouched: true, DeviceID: device, Session: relaySession,
		Helper: name, HelperUsername: acct.Username, HelperAvatar: h.helperAvatar(ctx, account), Via: pair.Via,
	})
}

// unattendedEnded writes the end of a vouched unattended session, with how
// long it ran.
func (h *handlers) unattendedEnded(v onboard.Vouched, ended time.Time) {
	if h.d.Audit == nil {
		return
	}
	seconds := int64(ended.Sub(v.Since).Round(time.Second) / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	details := unattendedDetails(v.DeviceID, "ended", "helper="+v.Helper, "started="+v.Since.UTC().Format(time.RFC3339),
		"duration_s="+strconv.FormatInt(seconds, 10), "relay_session="+v.Session)
	if err := h.d.Audit.WriteAbout(context.Background(), v.Actor, v.Account, auditUnattendedEnded, details, ""); err != nil {
		h.log.Warn("Audit entry "+auditUnattendedEnded+" failed:", err)
	}
}

// unattendedDetails is the detail line of an unattended access entry:
// "Unattended session to device <id> <what>" and key=value fields, which
// the console's audit log shows in its language.
func unattendedDetails(device, what string, fields ...string) string {
	return strings.Join(append([]string{"Unattended session to device " + device + " " + what}, fields...), "; ")
}

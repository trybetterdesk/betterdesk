package onboard

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/neodeskapp/neodesk/neodesk-server/console/authn"
	"github.com/neodeskapp/neodesk/neodesk-server/console/jsbind"
	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/onboard"
)

// maxPasswordLength bounds the session password the app hands over.
const maxPasswordLength = 128

type sessionKey struct{}

// requireSessionToken lets a request through that carries the session
// token of an open quick support session (Authorization: Bearer
// <token>); the handler finds the session with appSessionOf. Anything
// else is 401 invalid_session, also the token of a session that ended.
func (h *handlers) requireSessionToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := authn.ExtractBearerToken(r.Header.Get("Authorization"))
		if !ok {
			kit.JSON(w, r, http.StatusUnauthorized, refusal{Error: "invalid_session"})
			return
		}
		sess, err := h.sessions.ByToken(r.Context(), token)
		if errors.Is(err, onboard.ErrNotFound) {
			kit.JSON(w, r, http.StatusUnauthorized, refusal{Error: "invalid_session"})
			return
		}
		if err != nil && sess.ID == "" {
			h.log.Error("Quick support session:", err)
			kit.JSON(w, r, http.StatusInternalServerError, refusal{Error: "server_error"})
			return
		}
		// The viewer tells the helper when quick support takes only the
		// password because the app reaches the console over plain HTTP
		h.callers.NoteApp(sess.ID, kit.Secure(r))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

func appSessionOf(r *http.Request) onboard.Session {
	sess, _ := r.Context().Value(sessionKey{}).(onboard.Session)
	return sess
}

// appView is the session as the app sees it.
type appView struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
	DeviceID  string `json:"device_id"`
}

type appAnswer struct {
	Success bool    `json:"success"`
	Session appView `json:"session"`
}

func appAnswerOf(s onboard.Session) appAnswer {
	return appAnswer{Success: true, Session: appView{ID: s.ID, Status: s.Status, ExpiresAt: s.ExpiresAt, DeviceID: s.DeviceID}}
}

// appFail answers a refused step of the app: {success:false, error}.
func appFail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	kit.JSON(w, r, status, refusal{Error: code, Message: message})
}

// redeemAnswer is POST /api/support/redeem.
type redeemAnswer struct {
	Success      bool         `json:"success"`
	SessionToken string       `json:"session_token"`
	Session      appView      `json:"session"`
	Supporter    string       `json:"supporter"`
	Company      string       `json:"company"`
	Server       serverAnswer `json:"server"`
	Console      string       `json:"console"`
	// ReceiverOffer says whether the app may offer to stay on the
	// computer after the session, with the admission it enrolls with
	ReceiverOffer receiverOffer `json:"receiver_offer"`
}

// receiverOffer is the redeem answer's receiver_offer: allowed follows
// the console's setting; admission is a one-time secret that admits one
// computer in managed or locked mode for 24 hours (expires_at), null
// with expires_at when not allowed.
type receiverOffer struct {
	Allowed   bool    `json:"allowed"`
	Admission *string `json:"admission"`
	ExpiresAt *string `json:"expires_at"`
}

// receiverOfferFor is the offer for a session that was just opened. An
// offer the console can't make (the setting or the admission can't be
// read or made) is not allowed: the session itself still works.
func (h *handlers) receiverOfferFor(ctx context.Context, sessionID string) receiverOffer {
	if h.d.Store == nil {
		return receiverOffer{}
	}
	on, err := onboard.LoadReceiverOffer(ctx, h.d.Store)
	if err != nil {
		h.log.Warn("Quick support receiver offer:", err)
		return receiverOffer{}
	}
	if !on {
		return receiverOffer{}
	}
	adm, err := h.codes.Admission(ctx, sessionID)
	if err != nil {
		h.log.Warn("Quick support admission:", err)
		return receiverOffer{}
	}
	return receiverOffer{Allowed: true, Admission: &adm.Secret, ExpiresAt: &adm.ExpiresAt}
}

// redeemSupport answers POST /api/support/redeem with the body {code}:
// the quick support app spends the code and gets its session token, the
// supporter's name and how to reach the server.
func (h *handlers) redeemSupport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := kit.Bind(r, &body); err != nil || !onboard.ValidFormat(body.Code) {
		unusable(w, r)
		return
	}
	code, _, err := h.codes.Redeem(r.Context(), body.Code, onboard.KindSupport, nil)
	if errors.Is(err, onboard.ErrUnusable) {
		unusable(w, r)
		return
	}
	if err != nil {
		h.log.Error("Redeem support code:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	token, sess, err := h.sessions.Redeem(r.Context(), code)
	if err != nil {
		h.log.Error("Open quick support session:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	// The link's page follows the session by its code from here on
	if remembered, err := h.sessions.RememberCode(r.Context(), sess.ID, body.Code); err != nil {
		h.log.Warn("Note the code of the quick support session:", err)
	} else {
		sess = remembered
	}
	h.auditAs(r, 0, "quick_support_opened", "The quick support app opened session "+sess.ID+" of "+sess.CreatedBy)
	kit.JSON(w, r, http.StatusOK, redeemAnswer{
		Success: true, SessionToken: token, Session: appAnswerOf(sess).Session,
		Supporter: h.personName(r.Context(), sess.CreatedByID, sess.CreatedBy), Company: h.serverName(),
		Server: h.serverOf(r), Console: h.consoleOf(r).Base(),
		ReceiverOffer: h.receiverOfferFor(r.Context(), sess.ID),
	})
}

// auditAs writes an audit entry in the name of the account userID; 0 is
// none, for what a device or the quick support app did, which no account
// did. The details name the supporter.
func (h *handlers) auditAs(r *http.Request, userID int64, action, details string) {
	if h.d.Audit == nil {
		return
	}
	if err := h.d.Audit.Write(r.Context(), userID, action, details, kit.ClientIP(r)); err != nil {
		h.log.Warn("Audit entry "+action+" failed:", err)
	}
}

// appSession answers GET /api/support/session, which the app polls: the
// session's state. It also keeps the session open (onboard.IdleLimit).
func (h *handlers) appSession(w http.ResponseWriter, r *http.Request) {
	kit.JSON(w, r, http.StatusOK, appAnswerOf(appSessionOf(r)))
}

// appDevice answers POST /api/support/session/device with the body
// {device_id, uuid, hostname, platform, version}: the device the app runs
// on. A device the server does not know is admitted for the session (a
// temporary device, removed after it), put into the session's folder and
// given to the supporter.
func (h *handlers) appDevice(w http.ResponseWriter, r *http.Request) {
	sess := appSessionOf(r)
	if sess.Status != onboard.StatusOpened {
		appFail(w, r, http.StatusConflict, onboard.ErrState.Error(), "")
		return
	}
	var dev onboard.Device
	if err := kit.Bind(r, &dev); err != nil || !authn.IsDeviceID(strings.TrimSpace(dev.DeviceID)) {
		appFail(w, r, http.StatusBadRequest, "invalid_device", "")
		return
	}
	dev.DeviceID = strings.TrimSpace(dev.DeviceID)
	dev.PublicKey, dev.Temporary, dev.DisplayName = "", true, sess.Name
	created, err := h.codes.Admit(r.Context(), dev)
	var refused *onboard.RefusedError
	var invalid *onboard.InvalidDeviceError
	switch {
	case errors.As(err, &refused):
		// The session ends here: the supporter sees why and on which computer
		if _, err := h.sessions.Refuse(r.Context(), sess.ID, dev, refused.Code); err != nil {
			h.log.Warn("End refused quick support session:", err)
		}
		h.auditAs(r, 0, "quick_support_refused", "Quick support session "+sess.ID+" of "+sess.CreatedBy+" refused device "+dev.DeviceID+": "+refused.Reason)
		kit.JSON(w, r, http.StatusForbidden, refusal{Error: "device_refused", Message: refused.Reason, Reason: refused.Code})
		return
	case errors.As(err, &invalid):
		appFail(w, r, http.StatusBadRequest, "invalid_device", invalid.Reason)
		return
	case err != nil:
		h.log.Error("Admit quick support device:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	granted := false
	if created {
		ctx := r.Context()
		if sess.FolderID > 0 && h.d.DeviceGroups != nil {
			if err := h.d.DeviceGroups.AssignDeviceToFolder(ctx, jsbind.String(dev.DeviceID), jsbind.Number(float64(sess.FolderID))); err != nil {
				h.log.Warn("Put quick support device into its folder:", err)
			}
		}
		if h.d.Store != nil && sess.CreatedByID > 0 {
			insert := `INSERT INTO user_peer_grants (user_id, peer_id) VALUES (?, ?) ON CONFLICT DO NOTHING`
			if _, err := h.d.Store.Exec(ctx, insert, sess.CreatedByID, dev.DeviceID); err != nil {
				h.log.Warn("Give the supporter the quick support device:", err)
			} else {
				granted = true
			}
		}
	}
	updated, err := h.sessions.SetDevice(r.Context(), sess.ID, dev, created, granted)
	if errors.Is(err, onboard.ErrState) {
		appFail(w, r, http.StatusConflict, onboard.ErrState.Error(), "")
		return
	}
	if err != nil {
		h.log.Error("Record quick support device:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	h.auditAs(r, 0, "quick_support_device", "Quick support session "+sess.ID+" of "+sess.CreatedBy+" runs on device "+dev.DeviceID)
	kit.JSON(w, r, http.StatusOK, appAnswerOf(updated))
}

// appConsent answers POST /api/support/session/consent with the body
// {allowed, grants?}: the person's answer on their screen. Declined ends
// the session. Allowed gives the screen, the mouse and the keyboard, and
// what grants names of "clipboard" and "file_transfer"; the server turns
// everything else off for the supporter's sessions.
func (h *handlers) appConsent(w http.ResponseWriter, r *http.Request) {
	sess := appSessionOf(r)
	var body struct {
		Allowed *bool    `json:"allowed"`
		Grants  []string `json:"grants"`
	}
	if err := kit.Bind(r, &body); err != nil || body.Allowed == nil {
		appFail(w, r, http.StatusBadRequest, "invalid_body", "")
		return
	}
	updated, err := h.sessions.Consent(r.Context(), sess.ID, *body.Allowed, body.Grants)
	if errors.Is(err, onboard.ErrState) {
		appFail(w, r, http.StatusConflict, onboard.ErrState.Error(), "")
		return
	}
	if err != nil {
		h.log.Error("Record quick support consent:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	action := "quick_support_allowed"
	if !*body.Allowed {
		action = "quick_support_declined"
	}
	h.auditAs(r, 0, action, "Quick support session "+sess.ID+" of "+sess.CreatedBy+" on device "+sess.DeviceID)
	kit.JSON(w, r, http.StatusOK, appAnswerOf(updated))
}

// appPassword answers POST /api/support/session/password with the body
// {password}: the session password for the supporter, kept in memory
// until the supporter takes it or the session ends.
func (h *handlers) appPassword(w http.ResponseWriter, r *http.Request) {
	sess := appSessionOf(r)
	var body struct {
		Password string `json:"password"`
	}
	if err := kit.Bind(r, &body); err != nil || body.Password == "" || utf8.RuneCountInString(body.Password) > maxPasswordLength {
		appFail(w, r, http.StatusBadRequest, "invalid_password", "")
		return
	}
	if err := h.sessions.SetPassword(r.Context(), sess.ID, body.Password); errors.Is(err, onboard.ErrState) {
		appFail(w, r, http.StatusConflict, onboard.ErrState.Error(), "")
		return
	} else if err != nil {
		h.log.Error("Keep the session password:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	kit.JSON(w, r, http.StatusOK, map[string]bool{"success": true})
}

// appEnd answers POST /api/support/session/end: the app closed. The token
// stops working.
func (h *handlers) appEnd(w http.ResponseWriter, r *http.Request) {
	sess := appSessionOf(r)
	if _, err := h.sessions.End(r.Context(), sess.ID, onboard.EndedByCustomer); err != nil && !errors.Is(err, onboard.ErrState) {
		h.log.Error("End quick support session:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	h.auditAs(r, 0, "quick_support_ended", "The quick support app on device "+sess.DeviceID+" ended session "+sess.ID+" of "+sess.CreatedBy)
	kit.JSON(w, r, http.StatusOK, map[string]bool{"success": true})
}

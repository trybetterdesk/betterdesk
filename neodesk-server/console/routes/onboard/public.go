package onboard

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/neodeskapp/neodesk/neodesk-server/console/authn"
	"github.com/neodeskapp/neodesk/neodesk-server/console/clientrelease"
	"github.com/neodeskapp/neodesk/neodesk-server/console/httpx"
	"github.com/neodeskapp/neodesk/neodesk-server/console/jsbind"
	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/onboard"
)

// publicServer is the console as the public page names it. Address is
// the console's address with its scheme and port, which a client asks for
// when it joins with the code alone.
type publicServer struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	HTTPS   bool   `json:"https"`
	Address string `json:"address"`
}

// publicDownload is one package the page offers.
type publicDownload struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Format  string `json:"format"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	File    string `json:"file"`
	URL     string `json:"url"`
}

// publicAnswer is GET /api/onboard/public/{code}: what the pages /join/
// and /s/ show.
type publicAnswer struct {
	Success        bool             `json:"success"`
	Kind           string           `json:"kind"`
	Code           string           `json:"code"`
	DisplayCode    string           `json:"display_code"`
	ExpiresAt      string           `json:"expires_at"`
	Server         publicServer     `json:"server"`
	Publisher      string           `json:"publisher"`
	Supporter      string           `json:"supporter"`
	Company        string           `json:"company"`
	Downloads      []publicDownload `json:"downloads"`
	InstallCommand string           `json:"install_command,omitempty"`
	RunCommand     string           `json:"run_command,omitempty"`
	DeepLink       string           `json:"deep_link"`
	ReleaseError   string           `json:"release_error,omitempty"`
}

// lookupPublic reads the code of the path and answers the one refusal
// when it cannot be used.
func (h *handlers) lookupPublic(w http.ResponseWriter, r *http.Request) (string, onboard.Code, bool) {
	code := onboard.Normalize(r.PathValue("code"))
	if !onboard.ValidFormat(code) {
		unusable(w, r)
		return "", onboard.Code{}, false
	}
	rec, err := h.codes.Lookup(r.Context(), code)
	if errors.Is(err, onboard.ErrUnusable) {
		unusable(w, r)
		return "", onboard.Code{}, false
	}
	if err != nil {
		h.serverError(w, r, "Look up code:", err)
		return "", onboard.Code{}, false
	}
	return code, rec, true
}

// publicCode answers GET /api/onboard/public/{code}.
func (h *handlers) publicCode(w http.ResponseWriter, r *http.Request) {
	code, rec, ok := h.lookupPublic(w, r)
	if !ok {
		return
	}
	c := h.consoleOf(r)
	out := publicAnswer{
		Success: true, Kind: rec.Kind, Code: code, DisplayCode: onboard.Display(code), ExpiresAt: rec.ExpiresAt,
		Server:    publicServer{Name: h.serverName(), Host: c.Host, HTTPS: c.HTTPS, Address: c.Base()},
		Publisher: clientrelease.Publisher, Downloads: []publicDownload{},
		DeepLink: c.DeepLink(rec.Kind, code),
	}
	offers, err := h.releases.Offers(r.Context(), rec.Kind)
	if err != nil {
		out.ReleaseError = clientrelease.ErrUnavailable.Error()
	}
	for _, o := range offers {
		q := url.Values{"os": {o.OS}, "arch": {o.Arch}, "format": {o.Format}}
		out.Downloads = append(out.Downloads, publicDownload{
			OS: o.OS, Arch: o.Arch, Format: o.Format, Version: o.Version, Size: o.Size,
			File: c.FileName(rec.Kind, code, o.Ext()),
			URL:  "/api/onboard/public/" + code + "/download?" + q.Encode(),
		})
	}
	if rec.Kind == onboard.KindJoin {
		out.InstallCommand = "curl -fsSL '" + c.Base() + "/join/" + code + "/install.sh' | sudo sh"
	} else {
		out.RunCommand = "curl -fsSL '" + c.Base() + "/s/" + code + "/run.sh' | sh"
	}
	// Who sent the link: the page names them, as the mail does
	out.Supporter = h.personName(r.Context(), rec.CreatedByID, rec.CreatedBy)
	out.Company = h.serverName()
	kit.JSON(w, r, http.StatusOK, out)
}

// The states of a link as its page shows them.
const (
	// stateWaiting: the code still works; nobody used it yet.
	stateWaiting = "waiting"
	// stateOpened: the quick support app took the code and asks the person.
	stateOpened = "opened"
	// stateAllowed: the person let the supporter in.
	stateAllowed = "allowed"
	// stateEnded: the session is over.
	stateEnded = "ended"
)

// publicState answers GET /api/onboard/public/{code}/state with
// {success, state}: whether the quick support app took the link, so the
// open page can stop offering the download. A spent support code answers
// for its session; any other code that cannot be used is the usual 404.
func (h *handlers) publicState(w http.ResponseWriter, r *http.Request) {
	code := onboard.Normalize(r.PathValue("code"))
	if !onboard.ValidFormat(code) {
		unusable(w, r)
		return
	}
	sess, err := h.sessions.ByCode(r.Context(), code)
	switch {
	case err == nil:
		if state := stateOf(sess); state != "" {
			kit.JSON(w, r, http.StatusOK, map[string]any{"success": true, "state": state})
			return
		}
	case !errors.Is(err, onboard.ErrNotFound):
		h.serverError(w, r, "Look up the session of a code:", err)
		return
	}
	if _, _, ok := h.lookupPublic(w, r); ok {
		kit.JSON(w, r, http.StatusOK, map[string]any{"success": true, "state": stateWaiting})
	}
}

// stateOf is the page's state of a redeemed session; "" when it has none
// to show (a session that expired before anyone opened it).
func stateOf(sess onboard.Session) string {
	switch sess.Status {
	case onboard.StatusOpened, onboard.StatusAsking:
		return stateOpened
	case onboard.StatusAllowed:
		return stateAllowed
	case onboard.StatusDeclined, onboard.StatusEnded:
		return stateEnded
	}
	return ""
}

// contentTypes are the types the packages are served with.
var contentTypes = map[string]string{
	"exe":    "application/vnd.microsoft.portable-executable",
	"dmg":    "application/x-apple-diskimage",
	"deb":    "application/vnd.debian.binary-package",
	"rpm":    "application/x-rpm",
	"tar.gz": "application/gzip",
}

// download answers GET /api/onboard/public/{code}/download?os=&arch=&format=:
// the client package for that system under the code's file name. The
// code is not spent.
func (h *handlers) download(w http.ResponseWriter, r *http.Request) {
	code, rec, ok := h.lookupPublic(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f, offer, err := h.releases.Open(r.Context(), rec.Kind, q.Get("os"), q.Get("arch"), q.Get("format"))
	switch {
	case errors.Is(err, clientrelease.ErrNoPackage):
		kit.JSON(w, r, http.StatusNotFound, refusal{Error: "no_package"})
		return
	case err != nil:
		if !errors.Is(err, clientrelease.ErrUnavailable) {
			h.log.Error("Open client package:", err)
		}
		kit.JSON(w, r, http.StatusServiceUnavailable, refusal{Error: clientrelease.ErrUnavailable.Error()})
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		h.serverError(w, r, "Read client package:", err)
		return
	}
	name := h.consoleOf(r).FileName(rec.Kind, code, offer.Ext())
	w.Header().Set("Content-Type", contentTypes[offer.Format])
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "", info.ModTime(), f)
}

// scriptGone is what a script address answers for a code that cannot be
// used; curl -f stops on the status.
func scriptGone(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("This link has expired or was already used.\n"))
}

// script answers a shell script for an open code of the kind.
func (h *handlers) script(w http.ResponseWriter, r *http.Request, kind string, build func(base, code string) string) {
	code := onboard.Normalize(r.PathValue("code"))
	if !onboard.ValidFormat(code) {
		scriptGone(w)
		return
	}
	rec, err := h.codes.Lookup(r.Context(), code)
	if err != nil || rec.Kind != kind {
		if err != nil && !errors.Is(err, onboard.ErrUnusable) {
			h.log.Error("Look up code:", err)
		}
		scriptGone(w)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(build(h.consoleOf(r).Base(), code)))
}

// installScript answers GET /join/{code}/install.sh: the script that
// installs the client package and joins this server with the code.
func (h *handlers) installScript(w http.ResponseWriter, r *http.Request) {
	h.script(w, r, onboard.KindJoin, onboard.InstallScript)
}

// runScript answers GET /s/{code}/run.sh: the script that starts quick
// support from the portable package, without installing anything.
func (h *handlers) runScript(w http.ResponseWriter, r *http.Request) {
	h.script(w, r, onboard.KindSupport, onboard.RunScript)
}

// joinDevice is the body of POST /api/onboard/join.
type joinDevice struct {
	Code      string `json:"code"`
	DeviceID  string `json:"device_id"`
	UUID      string `json:"uuid"`
	Hostname  string `json:"hostname"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	PublicKey string `json:"public_key"`
}

// joinedDevice is the device as the client learns it.
type joinedDevice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FolderID *int64 `json:"folder_id"`
	// FolderName is the folder's name, for the client to show; "" without
	// a folder.
	FolderName string `json:"folder_name"`
}

// joinAnswer is POST /api/onboard/join.
type joinAnswer struct {
	Success     bool         `json:"success"`
	Server      serverAnswer `json:"server"`
	DeviceToken string       `json:"device_token"`
	Device      joinedDevice `json:"device"`
	Console     string       `json:"console"`
}

// auditJoinUnproved writes the audit entry of a join under an enrolled
// computer's ID that came without the proof of its key into the console's
// audit list (Security and audit): the device, the address (the entry's
// own) and why. The API server decides when one is due, once a minute per
// device, and counts the refusals it stands for.
func (h *handlers) auditJoinUnproved(r *http.Request, deviceID string, refused *onboard.RefusedError) {
	details := "Join of enrolled device " + deviceID + " refused without proof of its key (" + refused.Unproved + ")"
	if refused.Repeats > 0 {
		details += ", " + strconv.Itoa(refused.Repeats) + " more refused since the last entry"
	}
	h.auditAs(r, 0, "onboard_join_unproved", details)
}

// joinProofOf is the key proof a join carries in the headers
// X-ND-Enrollment-Timestamp, -Nonce and -Signature (the proof the client
// makes for its registration too), nil without them. The API server checks
// it against the key it bound to a device ID it already knows.
func joinProofOf(r *http.Request) *onboard.Proof {
	p := &onboard.Proof{
		Path:      httpx.RawPath(r),
		Timestamp: strings.TrimSpace(r.Header.Get("X-ND-Enrollment-Timestamp")),
		Nonce:     strings.TrimSpace(r.Header.Get("X-ND-Enrollment-Nonce")),
		Signature: strings.TrimSpace(r.Header.Get("X-ND-Enrollment-Signature")),
	}
	if p.Timestamp == "" && p.Nonce == "" && p.Signature == "" {
		return nil
	}
	return p
}

// join answers POST /api/onboard/join with the body {code, device_id,
// uuid, hostname, platform, version, public_key}: the client spends one
// use of an invite, its device is approved with the invite's name and put
// into its folder, and it gets how to reach the server and a device token,
// which no account holds (authn.IssueDeviceToken). A device ID the server
// knows joins only with the proof of its key (joinProofOf): the ID is no
// secret, and a join ends the device's earlier tokens.
func (h *handlers) join(w http.ResponseWriter, r *http.Request) {
	var body joinDevice
	if err := kit.Bind(r, &body); err != nil {
		appFail(w, r, http.StatusBadRequest, "invalid_body", "")
		return
	}
	if !onboard.ValidFormat(body.Code) {
		unusable(w, r)
		return
	}
	deviceID := strings.TrimSpace(body.DeviceID)
	if !authn.IsDeviceID(deviceID) {
		appFail(w, r, http.StatusBadRequest, "invalid_device", "invalid device_id")
		return
	}
	// The server keeps the client's address with a key it refuses
	ctx := authn.WithClientAddress(r.Context(), kit.ClientIP(r))
	rec, _, err := h.codes.Redeem(ctx, body.Code, onboard.KindJoin, &onboard.Device{
		DeviceID: deviceID, UUID: body.UUID, Hostname: body.Hostname, Platform: body.Platform,
		Version: body.Version, PublicKey: body.PublicKey, Proof: joinProofOf(r),
	})
	var refused *onboard.RefusedError
	var invalid *onboard.InvalidDeviceError
	switch {
	case errors.Is(err, onboard.ErrUnusable):
		unusable(w, r)
		return
	case errors.As(err, &refused):
		if refused.Audit {
			h.auditJoinUnproved(r, deviceID, refused)
		}
		kit.JSON(w, r, http.StatusForbidden, refusal{Error: "device_refused", Message: refused.Reason, Reason: refused.Code})
		return
	case errors.As(err, &invalid):
		appFail(w, r, http.StatusBadRequest, "invalid_device", invalid.Reason)
		return
	case err != nil:
		h.log.Error("Redeem invite:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}

	device := joinedDevice{ID: deviceID}
	if rec.MaxUses == 1 {
		device.Name = rec.Name
	}
	if rec.FolderID > 0 && h.d.DeviceGroups != nil {
		if err := h.d.DeviceGroups.AssignDeviceToFolder(ctx, jsbind.String(deviceID), jsbind.Number(float64(rec.FolderID))); err != nil {
			h.log.Error("Put joined device into its folder:", err)
		} else {
			folder := rec.FolderID
			device.FolderID = &folder
			device.FolderName = h.folderName(ctx, folder)
		}
	}
	creator := rec.CreatedByID
	if creator == 0 && h.d.Authn != nil {
		if account, err := h.d.Authn.UserByUsername(ctx, rec.CreatedBy); err == nil && account != nil {
			creator = account.ID.V
		}
	}
	if creator == 0 || h.d.Authn == nil {
		h.log.Error("Joined device without a device token: the invite's account is gone", deviceID)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	token, err := h.d.Authn.IssueDeviceToken(ctx, deviceID, "Issued at a join with invite "+rec.ID)
	if err == nil && token == "" {
		err = errors.New("the database has no device_tokens")
	}
	if err != nil {
		h.log.Error("Issue device token for joined device:", err)
		appFail(w, r, http.StatusInternalServerError, "server_error", "")
		return
	}
	h.auditAs(r, 0, "invite_redeemed", "Device "+deviceID+" joined with invite "+rec.ID+" of "+rec.CreatedBy)
	kit.JSON(w, r, http.StatusOK, joinAnswer{
		Success: true, Server: h.serverOf(r), DeviceToken: token, Device: device, Console: h.consoleOf(r).Base(),
	})
}

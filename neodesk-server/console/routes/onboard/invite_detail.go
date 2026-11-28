package onboard

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/onboard"
)

// inviteDevice is a computer that joined with an invite, as the invite
// sheet's steps start from it.
type inviteDevice struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname"`
	Platform   string `json:"platform"`
	FolderID   *int64 `json:"folder_id"`
	FolderName string `json:"folder_name"`
	Online     bool   `json:"online"`
	JoinedAt   string `json:"joined_at"`
	// DeviceType is what the computer runs as its NeoDesk reports it:
	// "neodesk-support" for the receiver app, "neodesk" for the full
	// desktop app, "" until it says
	DeviceType string `json:"device_type"`
}

// inviteRefusal is the last computer an invite's join refused. KeyRequest
// says its new key waits for an administrator (Approve new key).
type inviteRefusal struct {
	DeviceID   string `json:"device_id"`
	Reason     string `json:"reason"`
	At         string `json:"at"`
	KeyRequest bool   `json:"key_request"`
}

// inviteDetail is GET /api/onboard/invites/{id}.
type inviteDetail struct {
	Success bool           `json:"success"`
	Invite  invite         `json:"invite"`
	Devices []inviteDevice `json:"devices"`
	Refused *inviteRefusal `json:"refused"`
}

// getInvite answers GET /api/onboard/invites/{id}: the invite and the
// computers that joined with it, also once the joins used it up, until it
// would have expired. The invite sheet polls it to follow the join (there
// is no push of a join to the console).
func (h *handlers) getInvite(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if !codeID(id) {
		fail(w, r, http.StatusNotFound, "not_found")
		return
	}
	ctx := r.Context()
	state, err := h.codes.Invite(ctx, id)
	if errors.Is(err, onboard.ErrNotFound) {
		fail(w, r, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		h.serverError(w, r, "Read invite:", err)
		return
	}
	out := inviteDetail{Success: true, Invite: h.inviteOf(ctx, state.Code), Devices: []inviteDevice{}}
	for _, joined := range state.Joined {
		device, ok, err := h.joinedDevice(ctx, joined)
		if err != nil {
			h.serverError(w, r, "Read joined device:", err)
			return
		}
		if ok {
			out.Devices = append(out.Devices, device)
		}
	}
	if state.Refused != nil {
		refused := &inviteRefusal{DeviceID: state.Refused.DeviceID, Reason: state.Refused.Reason, At: state.Refused.At}
		if refused.Reason == "key_changed" {
			if refused.KeyRequest, err = h.codes.HasKeyRequest(ctx, refused.DeviceID); err != nil {
				h.serverError(w, r, "Read key request:", err)
				return
			}
		}
		out.Refused = refused
	}
	kit.JSON(w, r, http.StatusOK, out)
}

// joinedDevice reads a joined computer from the device table; ok is false
// for one that is gone since.
func (h *handlers) joinedDevice(ctx context.Context, joined onboard.Joined) (inviteDevice, bool, error) {
	d := inviteDevice{ID: joined.DeviceID, JoinedAt: joined.JoinedAt}
	if h.d.Store == nil {
		return d, false, nil
	}
	var name, hostname, platform, status, deviceType sql.NullString
	err := h.d.Store.QueryRow(ctx, `SELECT display_name, hostname, os, status, device_type FROM peers WHERE id = ? AND NOT soft_deleted`, joined.DeviceID).
		Scan(&name, &hostname, &platform, &status, &deviceType)
	if errors.Is(err, sql.ErrNoRows) {
		return d, false, nil
	}
	if err != nil {
		return d, false, err
	}
	d.Name, d.Hostname, d.Platform, d.DeviceType = name.String, hostname.String, platform.String, deviceType.String
	d.Online = strings.EqualFold(status.String, "ONLINE")
	var folder sql.NullInt64
	var folderName sql.NullString
	err = h.d.Store.QueryRow(ctx, `SELECT f.id, f.name FROM device_folder_assignments a JOIN folders f ON f.id = a.folder_id WHERE a.device_id = ?`, joined.DeviceID).
		Scan(&folder, &folderName)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return d, false, err
	case folder.Valid:
		id := folder.Int64
		d.FolderID, d.FolderName = &id, folderName.String
	}
	return d, true, nil
}

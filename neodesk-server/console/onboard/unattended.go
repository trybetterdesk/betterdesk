package onboard

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/console/goapi"
	"github.com/neodeskapp/neodesk/neodesk-server/policy/unattended"
)

// UnattendedPair is what the API server knows about the relay session a
// receiver asks about (UNATTENDED-CONTRACT.md): the account that opened
// it, how (Via "console" or "desktop"), and the device's inputs of the
// rule.
type UnattendedPair struct {
	Account      int64              `json:"account"`
	Via          string             `json:"via"`
	Mode         string             `json:"mode"`
	OrgOperators []string           `json:"org_operators"`
	Access       *unattended.Access `json:"access"`
}

// UnattendedCaller asks the API server about the relay session to
// deviceID. It answers the pair, or nil, the API server's refusal code
// (session_not_open, too_late, already_used, no_account) and the account
// the session names when the refusal carries one. The API server answers
// once per session, shared with CallerAccount.
func (s *Sessions) UnattendedCaller(ctx context.Context, deviceID, session string) (*UnattendedPair, string, int64, error) {
	resp, err := s.api.Request(ctx, http.MethodPost, "/unattended/caller",
		goapi.Body(map[string]string{"device_id": deviceID, "session": session}),
		goapi.ValidateStatus(func(int) bool { return true }))
	if err != nil {
		return nil, "", 0, fmt.Errorf("POST /unattended/caller: %w", err)
	}
	var out struct {
		UnattendedPair
		Error string `json:"error"`
	}
	if err := resp.Decode(&out); err != nil {
		return nil, "", 0, fmt.Errorf("POST /unattended/caller: answer %d is no JSON: %w", resp.Status, err)
	}
	switch {
	case resp.Status == http.StatusOK && out.Account > 0 && out.Via != "":
		pair := out.UnattendedPair
		return &pair, "", pair.Account, nil
	case resp.Status == http.StatusConflict && out.Error != "":
		return nil, out.Error, out.Account, nil
	}
	return nil, "", 0, fmt.Errorf("POST /unattended/caller: the API server answered %d %s", resp.Status, out.Error)
}

// Vouched is an unattended session the server vouched for, from the vouch
// until the relay ends it.
type Vouched struct {
	Session  string
	DeviceID string
	Account  int64
	// Actor is the account as the audit entry's actor: Account, or 0
	// when it has no row (never, for a vouched account)
	Actor  int64
	Helper string
	Via    string
	Since  time.Time
}

// vouchedMaxAge is how long the book keeps a session the relay never
// reported the end of (the relay's own live entries last as long).
const vouchedMaxAge = 7 * 24 * time.Hour

// UnattendedBook remembers, in memory, the unattended sessions the server
// vouched for, so that the relay's end of one writes its audit entry with
// the duration. A session that ends on another instance of a cluster, or
// after a restart, gets no end entry.
type UnattendedBook struct {
	mu    sync.Mutex
	now   func() time.Time
	pairs map[string]Vouched
	onEnd func(v Vouched, ended time.Time)
}

// NewUnattendedBook returns an empty book; now nil is time.Now.
func NewUnattendedBook(now func() time.Time) *UnattendedBook {
	if now == nil {
		now = time.Now
	}
	return &UnattendedBook{now: now, pairs: map[string]Vouched{}}
}

// OnEnd names what End calls for a vouched session; nil for nothing.
func (b *UnattendedBook) OnEnd(fn func(v Vouched, ended time.Time)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.onEnd = fn
	b.mu.Unlock()
}

// Add notes a vouched session.
func (b *UnattendedBook) Add(v Vouched) {
	if b == nil || v.Session == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for k, p := range b.pairs {
		if now.Sub(p.Since) > vouchedMaxAge {
			delete(b.pairs, k)
		}
	}
	b.pairs[v.Session] = v
}

// End is the relay's end of the relay session uuid: a vouched session
// leaves the book and goes to OnEnd. Other sessions are not noted.
func (b *UnattendedBook) End(uuid string) {
	if b == nil || uuid == "" {
		return
	}
	b.mu.Lock()
	v, ok := b.pairs[uuid]
	delete(b.pairs, uuid)
	fn := b.onEnd
	now := b.now()
	b.mu.Unlock()
	if ok && fn != nil {
		fn(v, now)
	}
}

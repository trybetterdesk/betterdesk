package onboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/console/goapi"
)

// The states of a quick support session.
const (
	// StatusWaiting: the link is out, nobody opened it yet.
	StatusWaiting = "waiting"
	// StatusOpened: the quick support app redeemed the code.
	StatusOpened = "opened"
	// StatusAsking: the app reported its device and asks the person.
	StatusAsking = "asking"
	// StatusAllowed: the person let the supporter in.
	StatusAllowed = "allowed"
	// StatusDeclined: the person said no. The session is over.
	StatusDeclined = "declined"
	// StatusEnded: the app closed, the supporter ended it, or the app
	// stopped calling in.
	StatusEnded = "ended"
	// StatusExpired: nobody opened the link in time.
	StatusExpired = "expired"
)

// Who ended a session.
const (
	EndedBySupporter = "supporter"
	EndedByCustomer  = "customer"
	EndedByTimeout   = "timeout"
	// EndedByTokenEnd: the API token the session was made with was
	// revoked, expired or deleted.
	EndedByTokenEnd = "token_ended"
	// EndedByRefused: the server refused the app's computer (a revoked or
	// blocked ID, a banned device); EndReason says why.
	EndedByRefused = "refused"
)

const (
	// SupportLifetime is how long a quick support link works.
	SupportLifetime = time.Hour
	// IdleLimit is how long an open session waits for the app to call in
	// before it ends.
	IdleLimit = 3 * time.Minute
	// DeviceRemoveAfter is how long a session's temporary device stays
	// after the session ended.
	DeviceRemoveAfter = 10 * time.Minute
	// seenEvery is how often a call of the app is written down.
	seenEvery = 30 * time.Second
)

// ErrState is a step the session's state does not allow.
var ErrState = errors.New("wrong_state")

// ErrNotYours is a supporter's step on a session another account made.
var ErrNotYours = errors.New("not_yours")

// ErrNoPassword is a password asked for that the app has not handed over.
var ErrNoPassword = errors.New("no_password")

// Session is one quick support session. The token's hash is kept; the
// token and the session password never are.
type Session struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	FolderID    int64  `json:"folder_id"`
	CreatedBy   string `json:"created_by"`
	CreatedByID int64  `json:"created_by_id"`
	// CreatedByToken is the console API token the session was made with,
	// "" for none: the end of that token ends the session.
	CreatedByToken string `json:"created_by_token,omitempty"`
	TokenHash      string `json:"token_hash,omitempty"`
	// CodeHash is the SHA-256 of the code the app redeemed (CodeHash), so
	// the page of the link can follow the session after the code is spent.
	CodeHash        string `json:"code_hash,omitempty"`
	DeviceID        string `json:"device_id"`
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	TemporaryDevice bool   `json:"temporary_device"`
	DeviceRemoved   bool   `json:"device_removed"`
	// Granted is true when the session gave its supporter the device
	// (user_peer_grants); the grant goes with the device.
	Granted bool `json:"granted"`
	// Grants is what the person allowed besides the screen, the mouse and
	// the keyboard (Grants*): the server turns everything else off for
	// the session (signal: limitToQuickSupport).
	Grants  []string `json:"grants,omitempty"`
	EndedBy string   `json:"ended_by"`
	// EndReason is the machine-readable reason of a session the server
	// ended (device_revoked, device_blocked, ...), "" otherwise.
	EndReason  string `json:"end_reason,omitempty"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	RedeemedAt string `json:"redeemed_at"`
	ConsentAt  string `json:"consent_at"`
	LastSeenAt string `json:"last_seen_at"`
	EndedAt    string `json:"ended_at"`
}

// Open reports whether the session has not ended.
func (s Session) Open() bool {
	switch s.Status {
	case StatusWaiting, StatusOpened, StatusAsking, StatusAllowed:
		return true
	}
	return false
}

// Sessions keeps the quick support sessions: in memory while the console
// runs, each change written to the API server's store, and the session
// passwords in memory only.
type Sessions struct {
	api *goapi.Client
	now func() time.Time

	loadMu sync.Mutex
	loaded bool

	mu   sync.Mutex
	byID map[string]*Session
	// byToken finds a session by its token's hash, also after the end:
	// ByToken opens only open sessions, FeedbackSession ended ones for
	// FeedbackWindow
	byToken   map[string]string
	passwords map[string]string
}

// NewSessions returns the sessions stored through api.
func NewSessions(api *goapi.Client, now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}
	return &Sessions{api: api, now: now, byID: map[string]*Session{}, byToken: map[string]string{}, passwords: map[string]string{}}
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseStamp(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// load reads the stored sessions once.
func (s *Sessions) load(ctx context.Context) error {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if s.loaded {
		return nil
	}
	resp, err := s.api.Request(ctx, http.MethodGet, "/onboard/sessions")
	if err != nil {
		return fmt.Errorf("load quick support sessions: %w", err)
	}
	var out struct {
		Sessions []Session `json:"sessions"`
	}
	if err := resp.Decode(&out); err != nil {
		return fmt.Errorf("load quick support sessions: %w", err)
	}
	s.mu.Lock()
	for i := range out.Sessions {
		sess := out.Sessions[i]
		if sess.ID == "" {
			continue
		}
		if _, known := s.byID[sess.ID]; known {
			continue
		}
		s.byID[sess.ID] = &sess
		if sess.TokenHash != "" {
			s.byToken[sess.TokenHash] = sess.ID
		}
	}
	s.mu.Unlock()
	s.loaded = true
	return nil
}

// save writes a session to the store.
func (s *Sessions) save(ctx context.Context, sess Session) error {
	if _, err := s.api.Request(ctx, http.MethodPut, "/onboard/sessions/"+sess.ID, goapi.Body(sess)); err != nil {
		return fmt.Errorf("store quick support session %s: %w", sess.ID, err)
	}
	return nil
}

// change applies fn to the session under the lock and stores the result.
// fn returns an error to change nothing.
func (s *Sessions) change(ctx context.Context, id string, fn func(sess *Session) error) (Session, error) {
	if err := s.load(ctx); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	cur, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return Session{}, ErrNotFound
	}
	next := *cur
	if err := fn(&next); err != nil {
		s.mu.Unlock()
		return Session{}, err
	}
	*cur = next
	if !next.Open() {
		delete(s.passwords, next.ID)
	}
	s.mu.Unlock()
	return next, s.save(ctx, next)
}

// Create stores a new waiting session for a support code.
func (s *Sessions) Create(ctx context.Context, code Code) (Session, error) {
	if err := s.load(ctx); err != nil {
		return Session{}, err
	}
	sess := Session{
		ID: code.ID, Status: StatusWaiting, Name: code.Name, Email: code.Email, FolderID: code.FolderID,
		CreatedBy: code.CreatedBy, CreatedByID: code.CreatedByID, CreatedByToken: code.CreatedByToken,
		CreatedAt: code.CreatedAt, ExpiresAt: code.ExpiresAt,
	}
	s.mu.Lock()
	s.byID[sess.ID] = &sess
	s.mu.Unlock()
	return sess, s.save(ctx, sess)
}

// Get returns a session.
func (s *Sessions) Get(ctx context.Context, id string) (Session, error) {
	if err := s.load(ctx); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byID[id]; ok {
		return *sess, nil
	}
	return Session{}, ErrNotFound
}

// OpenOf returns the open sessions an account made, newest first.
func (s *Sessions) OpenOf(ctx context.Context, userID int64) ([]Session, error) {
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	out := []Session{}
	for _, sess := range s.byID {
		if sess.Open() && sess.CreatedByID == userID {
			out = append(out, *sess)
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

// HasPassword reports whether a session password waits for the supporter.
func (s *Sessions) HasPassword(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.passwords[id]
	return ok
}

func newToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("session token: %w", err)
	}
	token = hex.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken is the hash a session token is kept and found by.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Redeem opens a waiting session for the app and returns the session
// token, which only this answer carries. A session that is missing (the
// code was made while the store could not be written) is made from the
// code.
func (s *Sessions) Redeem(ctx context.Context, code Code) (string, Session, error) {
	if _, err := s.Get(ctx, code.ID); errors.Is(err, ErrNotFound) {
		if _, err := s.Create(ctx, code); err != nil {
			return "", Session{}, err
		}
	} else if err != nil {
		return "", Session{}, err
	}
	token, hash, err := newToken()
	if err != nil {
		return "", Session{}, err
	}
	now := stamp(s.now())
	sess, err := s.change(ctx, code.ID, func(sess *Session) error {
		if sess.Status != StatusWaiting {
			return ErrState
		}
		sess.Status, sess.TokenHash, sess.RedeemedAt, sess.LastSeenAt = StatusOpened, hash, now, now
		return nil
	})
	if err != nil {
		return "", Session{}, err
	}
	s.mu.Lock()
	s.byToken[hash] = sess.ID
	s.mu.Unlock()
	return token, sess, nil
}

// CodeHash is how a session keeps the code it was opened with: the hex
// SHA-256 of the normalized code.
func CodeHash(code string) string {
	sum := sha256.Sum256([]byte(Normalize(code)))
	return hex.EncodeToString(sum[:])
}

// RememberCode notes on a session the code the app redeemed, for ByCode.
func (s *Sessions) RememberCode(ctx context.Context, id, code string) (Session, error) {
	hash := CodeHash(code)
	return s.change(ctx, id, func(sess *Session) error {
		sess.CodeHash = hash
		return nil
	})
}

// ByCode returns the session that was opened with code. A session that
// was never redeemed, or whose code is not known, is ErrNotFound.
func (s *Sessions) ByCode(ctx context.Context, code string) (Session, error) {
	if err := s.load(ctx); err != nil {
		return Session{}, err
	}
	hash := CodeHash(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.byID {
		if sess.CodeHash != "" && subtle.ConstantTimeCompare([]byte(sess.CodeHash), []byte(hash)) == 1 && sess.RedeemedAt != "" {
			return *sess, nil
		}
	}
	return Session{}, ErrNotFound
}

// ByToken returns the open session of a session token and notes the
// app's call. Any other token, and the token of a session that ended, is
// ErrNotFound.
func (s *Sessions) ByToken(ctx context.Context, token string) (Session, error) {
	if len(token) != 64 {
		return Session{}, ErrNotFound
	}
	if err := s.load(ctx); err != nil {
		return Session{}, err
	}
	hash := HashToken(token)
	s.mu.Lock()
	id, ok := s.byToken[hash]
	var sess *Session
	if ok {
		sess = s.byID[id]
	}
	if sess == nil || !sess.Open() || subtle.ConstantTimeCompare([]byte(sess.TokenHash), []byte(hash)) != 1 {
		s.mu.Unlock()
		return Session{}, ErrNotFound
	}
	now := s.now()
	last, _ := parseStamp(sess.LastSeenAt)
	write := now.Sub(last) >= seenEvery
	if write {
		sess.LastSeenAt = stamp(now)
	}
	out := *sess
	s.mu.Unlock()
	if write {
		if err := s.save(ctx, out); err != nil {
			return out, err
		}
	}
	return out, nil
}

// WasAllowed reports whether the person let the supporter in: the session
// is allowed, or ended after it was.
func (s Session) WasAllowed() bool {
	return s.ConsentAt != "" && (s.Status == StatusAllowed || s.Status == StatusEnded)
}

// FeedbackSession returns the session of a session token for the
// feedback routes: an open session, or one that ended at most
// FeedbackWindow ago. Any other token is ErrNotFound; a session the person
// never allowed (declined, ended or still open before Allow) is ErrState
// with the session. It does not note a call of the app.
func (s *Sessions) FeedbackSession(ctx context.Context, token string) (Session, error) {
	if len(token) != 64 {
		return Session{}, ErrNotFound
	}
	if err := s.load(ctx); err != nil {
		return Session{}, err
	}
	hash := HashToken(token)
	s.mu.Lock()
	var sess Session
	found := false
	if id, ok := s.byToken[hash]; ok {
		if cur := s.byID[id]; cur != nil && subtle.ConstantTimeCompare([]byte(cur.TokenHash), []byte(hash)) == 1 {
			sess, found = *cur, true
		}
	}
	s.mu.Unlock()
	if !found {
		return Session{}, ErrNotFound
	}
	if !sess.Open() {
		ended, ok := parseStamp(sess.EndedAt)
		if !ok || s.now().Sub(ended) > FeedbackWindow {
			return Session{}, ErrNotFound
		}
	}
	if !sess.WasAllowed() {
		return sess, ErrState
	}
	return sess, nil
}

// SetDevice records the device the app runs on and moves the session to
// asking. temporary marks a device the session made; granted a peer grant
// it gave the supporter.
func (s *Sessions) SetDevice(ctx context.Context, id string, dev Device, temporary, granted bool) (Session, error) {
	return s.change(ctx, id, func(sess *Session) error {
		if sess.Status != StatusOpened {
			return ErrState
		}
		sess.Status = StatusAsking
		sess.DeviceID, sess.Hostname, sess.Platform = dev.DeviceID, dev.Hostname, dev.Platform
		sess.TemporaryDevice, sess.Granted = temporary, granted
		return nil
	})
}

// Refuse ends an opened session whose computer the server refused, with
// the computer it was and the reason.
func (s *Sessions) Refuse(ctx context.Context, id string, dev Device, reason string) (Session, error) {
	now := stamp(s.now())
	return s.change(ctx, id, func(sess *Session) error {
		if sess.Status != StatusOpened {
			return ErrState
		}
		sess.Status, sess.EndedAt, sess.EndedBy, sess.EndReason = StatusEnded, now, EndedByRefused, reason
		sess.DeviceID, sess.Hostname, sess.Platform = dev.DeviceID, dev.Hostname, dev.Platform
		return nil
	})
}

// What the person can allow on the consent screen besides the screen, the
// mouse and the keyboard.
const (
	GrantClipboard    = "clipboard"
	GrantFileTransfer = "file_transfer"
)

// KnownGrant reports whether g is a grant of the consent screen.
func KnownGrant(g string) bool { return g == GrantClipboard || g == GrantFileTransfer }

// Consent records the person's answer: allowed, with what they allowed
// besides the screen, the mouse and the keyboard (grants), or declined,
// which ends the session.
func (s *Sessions) Consent(ctx context.Context, id string, allowed bool, grants []string) (Session, error) {
	now := stamp(s.now())
	return s.change(ctx, id, func(sess *Session) error {
		if sess.Status != StatusAsking {
			return ErrState
		}
		sess.ConsentAt = now
		if allowed {
			sess.Status = StatusAllowed
			sess.Grants = nil
			for _, g := range grants {
				if KnownGrant(g) && !slices.Contains(sess.Grants, g) {
					sess.Grants = append(sess.Grants, g)
				}
			}
			return nil
		}
		sess.Status, sess.EndedAt, sess.EndedBy = StatusDeclined, now, EndedByCustomer
		return nil
	})
}

// SetPassword keeps the session password the app hands over, in memory,
// for the supporter. It replaces one the supporter has not taken.
func (s *Sessions) SetPassword(ctx context.Context, id, password string) error {
	sess, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.byID[id]; cur == nil || cur.Status != StatusAllowed || sess.Status != StatusAllowed {
		return ErrState
	}
	s.passwords[id] = password
	return nil
}

// TakePassword hands the session password to the account that made the
// session, once: it is forgotten as it is handed over.
func (s *Sessions) TakePassword(ctx context.Context, id string, userID int64) (string, error) {
	if err := s.load(ctx); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return "", ErrNotFound
	}
	if sess.CreatedByID != userID {
		return "", ErrNotYours
	}
	password, ok := s.passwords[id]
	if !ok || sess.Status != StatusAllowed {
		return "", ErrNoPassword
	}
	delete(s.passwords, id)
	return password, nil
}

// TakePasswordForDevice is TakePassword for the allowed session of the
// account on a device: what the browser viewer asks when the device wants
// a password. ErrNoPassword when there is none.
func (s *Sessions) TakePasswordForDevice(ctx context.Context, deviceID string, userID int64) (string, error) {
	if err := s.load(ctx); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.byID {
		if sess.Status != StatusAllowed || sess.DeviceID != deviceID || sess.CreatedByID != userID {
			continue
		}
		if password, ok := s.passwords[id]; ok {
			delete(s.passwords, id)
			return password, nil
		}
	}
	return "", ErrNoPassword
}

// OpenOnDevice returns the newest session of the account on a device that
// still asks or was allowed.
func (s *Sessions) OpenOnDevice(ctx context.Context, deviceID string, userID int64) (Session, bool) {
	if err := s.load(ctx); err != nil {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *Session
	for _, sess := range s.byID {
		if sess.DeviceID != deviceID || sess.CreatedByID != userID || (sess.Status != StatusAsking && sess.Status != StatusAllowed) {
			continue
		}
		if found == nil || sess.CreatedAt > found.CreatedAt {
			found = sess
		}
	}
	if found == nil {
		return Session{}, false
	}
	return *found, true
}

// End ends an open session; by says who. The token stops working and the
// password is forgotten.
func (s *Sessions) End(ctx context.Context, id, by string) (Session, error) {
	now := stamp(s.now())
	return s.change(ctx, id, func(sess *Session) error {
		if !sess.Open() {
			return ErrState
		}
		if sess.Status == StatusWaiting {
			sess.Status = StatusExpired
		} else {
			sess.Status = StatusEnded
		}
		sess.EndedAt, sess.EndedBy = now, by
		return nil
	})
}

// EndMadeWith ends the open sessions made with the console API token
// token, as the supporter's End does: the app's token stops working and
// a password that waits is forgotten. It returns the ids it ended.
func (s *Sessions) EndMadeWith(ctx context.Context, token string) ([]string, error) {
	if token == "" {
		return nil, nil
	}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	var ids []string
	s.mu.Lock()
	for id, sess := range s.byID {
		if sess.Open() && sess.CreatedByToken == token {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	sort.Strings(ids)
	var ended []string
	var errs []error
	for _, id := range ids {
		if _, err := s.End(ctx, id, EndedByTokenEnd); err != nil && !errors.Is(err, ErrState) {
			errs = append(errs, err)
			continue
		}
		ended = append(ended, id)
	}
	return ended, errors.Join(errs...)
}

// Sweep ends what time ends: a waiting session whose link expired, an
// open one whose app stopped calling in for IdleLimit. It returns the
// sessions whose temporary device is due for removal (DeviceRemoveAfter
// after the end).
func (s *Sessions) Sweep(ctx context.Context) ([]Session, error) {
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	now := s.now()
	var expire, idle []string
	var due []Session
	s.mu.Lock()
	for id, sess := range s.byID {
		switch {
		case sess.Status == StatusWaiting:
			if t, ok := parseStamp(sess.ExpiresAt); !ok || !now.Before(t) {
				expire = append(expire, id)
			}
		case sess.Open():
			if t, ok := parseStamp(sess.LastSeenAt); !ok || now.Sub(t) >= IdleLimit {
				idle = append(idle, id)
			}
		case sess.TemporaryDevice && !sess.DeviceRemoved:
			if t, ok := parseStamp(sess.EndedAt); !ok || now.Sub(t) >= DeviceRemoveAfter {
				due = append(due, *sess)
			}
		}
	}
	// A device a later session uses again is that session's to remove
	var handed []string
	kept := due[:0]
	for _, d := range due {
		if s.deviceTakenOver(d) {
			handed = append(handed, d.ID)
		} else {
			kept = append(kept, d)
		}
	}
	due = kept
	s.mu.Unlock()
	var errs []error
	for _, id := range handed {
		if err := s.DeviceRemoved(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	for _, id := range expire {
		if _, err := s.End(ctx, id, EndedByTimeout); err != nil && !errors.Is(err, ErrState) {
			errs = append(errs, err)
		}
	}
	for _, id := range idle {
		if _, err := s.End(ctx, id, EndedByTimeout); err != nil && !errors.Is(err, ErrState) {
			errs = append(errs, err)
		}
	}
	return due, errors.Join(errs...)
}

// deviceTakenOver reports whether another session that has not given up
// the ended session's device uses it now. The caller holds s.mu.
func (s *Sessions) deviceTakenOver(ended Session) bool {
	for id, other := range s.byID {
		later := other.CreatedAt > ended.CreatedAt || (other.CreatedAt == ended.CreatedAt && id > ended.ID)
		if later && other.DeviceID == ended.DeviceID && (other.Open() || (other.TemporaryDevice && !other.DeviceRemoved)) {
			return true
		}
	}
	return false
}

// DeviceRemoved notes that a session's temporary device is gone.
func (s *Sessions) DeviceRemoved(ctx context.Context, id string) error {
	_, err := s.change(ctx, id, func(sess *Session) error {
		sess.DeviceRemoved = true
		return nil
	})
	return err
}

// Prune deletes the records of sessions that ended more than keep ago.
func (s *Sessions) Prune(ctx context.Context, keep time.Duration) error {
	if err := s.load(ctx); err != nil {
		return err
	}
	now := s.now()
	var old []string
	s.mu.Lock()
	for id, sess := range s.byID {
		if sess.Open() || (sess.TemporaryDevice && !sess.DeviceRemoved) {
			continue
		}
		if t, ok := parseStamp(sess.EndedAt); !ok || now.Sub(t) > keep {
			old = append(old, id)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, id := range old {
		if _, err := s.api.Request(ctx, http.MethodDelete, "/onboard/sessions/"+id); err != nil {
			errs = append(errs, fmt.Errorf("delete quick support session %s: %w", id, err))
			continue
		}
		s.mu.Lock()
		if sess := s.byID[id]; sess != nil && s.byToken[sess.TokenHash] == id {
			delete(s.byToken, sess.TokenHash)
		}
		delete(s.byID, id)
		s.mu.Unlock()
	}
	return errors.Join(errs...)
}

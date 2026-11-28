package onboard_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/api"
	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/console"
	consoleconfig "github.com/neodeskapp/neodesk/neodesk-server/console/config"
	"github.com/neodeskapp/neodesk/neodesk-server/console/httpx"
	"github.com/neodeskapp/neodesk/neodesk-server/console/kit"
	"github.com/neodeskapp/neodesk/neodesk-server/console/session"
	"github.com/neodeskapp/neodesk/neodesk-server/console/store"
	"github.com/neodeskapp/neodesk/neodesk-server/console/store/storetest"
	"github.com/neodeskapp/neodesk/neodesk-server/db"
	"github.com/neodeskapp/neodesk/neodesk-server/peer"
	"github.com/neodeskapp/neodesk/neodesk-server/relay"
	"github.com/neodeskapp/neodesk/neodesk-server/security"
)

var roleIDs = map[string]int64{
	"admin": 1, "super_admin": 2, "server_admin": 3, "global_admin": 4,
	"operator": 5, "viewer": 6, "guest_issuer": 7,
}

// world is a console with its API server on one database, the client
// packages in a folder, and a browser per role.
type world struct {
	t     *testing.T
	db    *store.DB
	gdb   db.Database
	deps  *kit.Deps
	front *httptest.Server
	// blocklist is the API server's
	blocklist *security.Blocklist
	// api is the API server's listener, where devices register
	api http.Handler
}

func newWorld(t *testing.T, sdb *store.DB) *world {
	t.Helper()
	ctx := context.Background()
	for role, id := range roleIDs {
		if _, err := sdb.Exec(ctx, "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, 'x', ?)", id, "e2e_"+role, role); err != nil {
			t.Fatalf("insert user: %v", err)
		}
	}
	if _, err := sdb.Exec(ctx, "UPDATE users SET first_name = 'Olga', last_name = 'Operator' WHERE id = 5"); err != nil {
		t.Fatal(err)
	}
	gdb := storetest.GoServer(t, sdb)
	cfg := config.DefaultConfig()
	cfg.EnrollmentMode = config.EnrollmentModeManaged
	// The relay's live sessions are the shared registry's, which a test
	// fills with relay.AuthorizeRelayPairForSession and two claims
	apiSrv := api.New(cfg, gdb, peer.NewMap(), relay.New(cfg), "test")
	bl := security.NewBlocklist()
	apiSrv.SetBlocklist(bl)

	packages := t.TempDir()
	for name, data := range map[string]string{
		"neodesk-1.4.6-windows-x86_64.exe":           "windows exe",
		"neodesk-1.4.6-linux-x86_64.deb":             "debian package",
		"neodesk-1.4.6-linux-x86_64-portable.tar.gz": "portable tar",
	} {
		if err := os.WriteFile(filepath.Join(packages, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data := t.TempDir()
	env := map[string]string{
		"SESSION_SECRET":             "onboard-secret-0123456789abcdef0123456789abcdef",
		"NEODESK_CLIENT_RELEASE_DIR": packages,
	}
	// The app's requests come through a proxy on loopback, which names the
	// scheme (X-Forwarded-Proto), as on a console behind a reverse proxy
	trust, err := httpx.ParseTrustProxy("loopback")
	if err != nil {
		t.Fatal(err)
	}
	ccfg := &consoleconfig.Config{
		Host: "127.0.0.1", NodeEnv: "development", DataDir: data,
		UploadsDir: filepath.Join(data, "uploads"), LangDir: filepath.Join("..", "..", "static", "files", "lang"),
		WebUIDir: filepath.Join(data, "no-build"), DefaultLanguage: "en",
		Getenv:     func(key string) string { return env[key] },
		TrustProxy: trust,
	}
	s, err := console.New(ctx, console.Options{Config: ccfg, Store: sdb, API: apiSrv.InternalHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	d := s.Deps()
	s.Router().Get("/__test/signin/{role}", func(rw http.ResponseWriter, r *http.Request) {
		role := r.PathValue("role")
		sess := kit.Session(r)
		_ = sess.Regenerate()
		if _, err := sess.Establish(session.User{ID: roleIDs[role], Username: "e2e_" + role, Role: role}, d.Sessions.ClientMeta(r, "")); err != nil {
			t.Errorf("establish: %v", err)
		}
		kit.OK(rw, r, nil)
	})
	s.Router().Get("/__test/token", func(rw http.ResponseWriter, r *http.Request) {
		kit.JSON(rw, r, http.StatusOK, map[string]string{"token": kit.CSRFToken(r)})
	})
	w := &world{t: t, db: sdb, gdb: gdb, deps: d, front: httptest.NewServer(s), blocklist: bl, api: apiSrv.ListenerHandler()}
	t.Cleanup(w.front.Close)
	return w
}

type answer struct {
	status int
	header http.Header
	body   string
}

func (a answer) json(t *testing.T) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(a.body), &out); err != nil {
		t.Fatalf("not JSON: %v: %s", err, a.body)
	}
	return out
}

// browser keeps one role's cookies and CSRF token.
type browser struct {
	w       *world
	cookies map[string]string
	token   string
	// ip is the client address the requests come from (X-Forwarded-For
	// is not trusted, so each browser here is the test's loopback).
	headers map[string]string
}

func (w *world) browser(role string) *browser {
	b := &browser{w: w, cookies: map[string]string{}, headers: map[string]string{}}
	if role != "" {
		if res := b.do(http.MethodGet, "/__test/signin/"+role, ""); res.status != http.StatusOK {
			w.t.Fatalf("sign in %s: %d %s", role, res.status, res.body)
		}
		b.token, _ = b.do(http.MethodGet, "/__test/token", "").json(w.t)["token"].(string)
	}
	return b
}

var client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 30 * time.Second}

func (b *browser) do(method, path, body string, header ...string) answer {
	b.w.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, b.w.front.URL+path, reader)
	if err != nil {
		b.w.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && b.token != "" {
		req.Header.Set("X-CSRF-Token", b.token)
	}
	req.Header.Set("Accept", "application/json")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	var pairs []string
	for k, v := range b.cookies {
		pairs = append(pairs, k+"="+v)
	}
	if len(pairs) > 0 {
		req.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
	res, err := client.Do(req)
	if err != nil {
		b.w.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	for _, c := range res.Cookies() {
		b.cookies[c.Name] = c.Value
	}
	return answer{status: res.StatusCode, header: res.Header, body: string(raw)}
}

// app is a client without a session: the desktop client or the quick
// support app.
func (w *world) app() *browser { return w.browser("") }

func str(m map[string]any, path ...string) string {
	var v any = m
	for _, p := range path {
		o, _ := v.(map[string]any)
		v = o[p]
	}
	s, _ := v.(string)
	return s
}

var token64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestInvitesNeedEnrollmentApprove(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	// Signed out, a write stops at the CSRF gate; a read asks for a session
	for path, list := range map[string]string{"/api/onboard/invites": "invites", "/api/support/sessions": "sessions"} {
		if res := w.app().do(http.MethodGet, path, ""); res.status != http.StatusUnauthorized {
			t.Errorf("%s signed out: %d %s", list, res.status, res.body)
		}
	}
	for role, want := range map[string]int{"": 403, "viewer": 403, "operator": 403, "guest_issuer": 403, "global_admin": 201, "admin": 201} {
		res := w.browser(role).do(http.MethodPost, "/api/onboard/invites", `{}`)
		if res.status != want {
			t.Errorf("%q: %d %s, want %d", role, res.status, res.body, want)
		}
	}
	for role, want := range map[string]int{"": 403, "viewer": 403, "guest_issuer": 403, "operator": 201} {
		res := w.browser(role).do(http.MethodPost, "/api/support/sessions", `{}`)
		if res.status != want {
			t.Errorf("support %q: %d %s, want %d", role, res.status, res.body, want)
		}
	}
}

func TestJoinFlow(t *testing.T) {
	storetest.EachMigrated(t, func(t *testing.T, sdb *store.DB) {
		w := newWorld(t, sdb)
		admin := w.browser("admin")
		res := admin.do(http.MethodPost, "/api/onboard/invites", `{"name":"Reception PC","lifetime_hours":24,"uses":1}`)
		if res.status != http.StatusCreated {
			t.Fatalf("create: %d %s", res.status, res.body)
		}
		made := res.json(t)
		code := str(made, "code")
		if len(code) != 8 || !strings.HasSuffix(str(made, "link"), "/join/"+code) || str(made, "display_code") != code[:4]+"-"+code[4:] {
			t.Fatalf("answer %v", made)
		}
		if res = admin.do(http.MethodGet, "/api/onboard/invites", ""); !strings.Contains(res.body, `"name":"Reception PC"`) || strings.Contains(res.body, code) {
			t.Fatalf("list: %s", res.body)
		}

		visitor := w.app()
		page := visitor.do(http.MethodGet, "/api/onboard/public/"+strings.ToLower(code[:4])+"-"+code[4:], "")
		if page.status != http.StatusOK {
			t.Fatalf("public: %d %s", page.status, page.body)
		}
		p := page.json(t)
		if str(p, "kind") != "join" || !strings.Contains(str(p, "install_command"), "/join/"+code+"/install.sh") || str(p, "publisher") != "Rath & Blume GbR" {
			t.Fatalf("public %v", p)
		}
		// The address a client asks for with the code alone (L340)
		if str(p, "server", "address") != w.front.URL {
			t.Errorf("server address %q, want %q", str(p, "server", "address"), w.front.URL)
		}
		downloads, _ := p["downloads"].([]any)
		if len(downloads) != 2 {
			t.Fatalf("downloads %v", downloads)
		}
		exe := downloads[0].(map[string]any)
		file := str(exe, "file")
		if !regexp.MustCompile(`^NeoDesk-Setup-127\.0\.0\.1_\d+_http-` + code + `\.exe$`).MatchString(file) {
			t.Fatalf("file name %q", file)
		}
		dl := visitor.do(http.MethodGet, str(exe, "url"), "")
		if dl.status != http.StatusOK || dl.body != "windows exe" || dl.header.Get("Content-Disposition") != `attachment; filename="`+file+`"` {
			t.Fatalf("download: %d %q %v", dl.status, dl.body, dl.header)
		}
		script := visitor.do(http.MethodGet, "/join/"+code+"/install.sh", "")
		if script.status != http.StatusOK || !strings.Contains(script.body, "CODE='"+code+"'") {
			t.Fatalf("install.sh: %d %s", script.status, script.body)
		}

		client := w.app()
		joined := client.do(http.MethodPost, "/api/onboard/join", `{"code":"`+code+`","device_id":"123456789","uuid":"u-1","hostname":"reception","platform":"Windows"}`)
		if joined.status != http.StatusOK {
			t.Fatalf("join: %d %s", joined.status, joined.body)
		}
		j := joined.json(t)
		token := str(j, "device_token")
		if !token64.MatchString(token) || str(j, "device", "name") != "Reception PC" || str(j, "server", "id_server") == "" {
			t.Fatalf("join answer %v", j)
		}
		peerRow, err := w.gdb.GetPeer("123456789")
		if err != nil || peerRow == nil || peerRow.DisplayName != "Reception PC" {
			t.Fatalf("the device is not approved with its name: %+v %v", peerRow, err)
		}
		if auth, err := w.deps.Authn.RequireDeviceToken(context.Background(), "Bearer "+token); err != nil || auth.DeviceID != "123456789" {
			t.Fatalf("the device token is not one: %+v %v", auth, err)
		}

		// Used once: the code is gone everywhere, with one answer.
		gone := `{"success":false,"error":"invalid_or_expired"}`
		for _, res := range []answer{
			client.do(http.MethodPost, "/api/onboard/join", `{"code":"`+code+`","device_id":"223456789"}`),
			visitor.do(http.MethodGet, "/api/onboard/public/"+code, ""),
			visitor.do(http.MethodGet, "/api/onboard/public/ZZZZZZZZ", ""),
			client.do(http.MethodPost, "/api/onboard/join", `{"code":"ZZZZ-ZZZZ","device_id":"223456789"}`),
		} {
			if res.status != http.StatusNotFound || strings.TrimSpace(res.body) != gone {
				t.Errorf("after use: %d %s", res.status, res.body)
			}
		}
		if res := visitor.do(http.MethodGet, "/join/"+code+"/install.sh", ""); res.status != http.StatusNotFound {
			t.Errorf("install.sh after use: %d", res.status)
		}
	})
}

func TestJoinCodeIntoAFolder(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	ctx := context.Background()
	if _, err := w.db.Exec(ctx, `INSERT INTO folders (id, name) VALUES (7, 'Front office')`); err != nil {
		t.Fatal(err)
	}
	admin := w.browser("admin")
	if res := admin.do(http.MethodPost, "/api/onboard/invites", `{"folder_id":99}`); res.status != http.StatusBadRequest || str(res.json(t), "code") != "invalid_folder" {
		t.Fatalf("unknown folder: %d %s", res.status, res.body)
	}
	res := admin.do(http.MethodPost, "/api/onboard/invites", `{"folder_id":7,"uses":2}`)
	if res.status != http.StatusCreated || !strings.Contains(res.body, `"folder_name":"Front office"`) {
		t.Fatalf("create: %d %s", res.status, res.body)
	}
	code := str(res.json(t), "code")
	// The join answer names the folder, so the client can show it (L204)
	joined := w.app().do(http.MethodPost, "/api/onboard/join", `{"code":"`+code+`","device_id":"323456789","hostname":"desk-1"}`)
	if joined.status != http.StatusOK || str(joined.json(t), "device", "folder_name") != "Front office" {
		t.Fatalf("join: %d %s", joined.status, joined.body)
	}
	var folder int64
	if err := w.db.QueryRow(ctx, `SELECT folder_id FROM device_folder_assignments WHERE device_id = ?`, "323456789").Scan(&folder); err != nil || folder != 7 {
		t.Fatalf("folder %d %v", folder, err)
	}
	// A code for two computers is still open after the first.
	if res := w.app().do(http.MethodGet, "/api/onboard/public/"+code, ""); res.status != http.StatusOK {
		t.Fatalf("second use: %d %s", res.status, res.body)
	}
}

func TestCodeRoutesAreRateLimitedPerAddress(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	visitor := w.app()
	for i := 0; i < 20; i++ {
		if res := visitor.do(http.MethodGet, "/api/onboard/public/ZZZZZZZZ", ""); res.status != http.StatusNotFound {
			t.Fatalf("try %d: %d", i, res.status)
		}
	}
	res := visitor.do(http.MethodPost, "/api/onboard/join", `{"code":"ZZZZZZZZ","device_id":"123456789"}`)
	if res.status != http.StatusTooManyRequests || res.header.Get("Retry-After") == "" {
		t.Fatalf("try 21: %d %s", res.status, res.body)
	}
}

func TestQuickSupportFlow(t *testing.T) {
	storetest.EachMigrated(t, func(t *testing.T, sdb *store.DB) {
		w := newWorld(t, sdb)
		operator := w.browser("operator")
		admin := w.browser("admin")
		res := operator.do(http.MethodPost, "/api/support/sessions", `{"name":"Ana"}`)
		if res.status != http.StatusCreated {
			t.Fatalf("create: %d %s", res.status, res.body)
		}
		made := res.json(t)
		code, id := str(made, "code"), str(made, "session", "id")
		if str(made, "session", "status") != "waiting" || !strings.HasSuffix(str(made, "link"), "/s/"+code) {
			t.Fatalf("answer %v", made)
		}
		if res := admin.do(http.MethodGet, "/api/support/sessions/"+id, ""); res.status != http.StatusNotFound {
			t.Fatalf("another account reads the session: %d", res.status)
		}

		page := w.app().do(http.MethodGet, "/api/onboard/public/"+code, "")
		if p := page.json(t); str(p, "kind") != "support" || str(p, "supporter") != "Olga Operator" || !strings.Contains(str(p, "run_command"), "/s/"+code+"/run.sh") {
			t.Fatalf("public %v", p)
		}
		if res := w.app().do(http.MethodPost, "/api/onboard/join", `{"code":"`+code+`","device_id":"123456789"}`); res.status != http.StatusNotFound {
			t.Fatalf("a support code joined a device: %d %s", res.status, res.body)
		}

		app := w.app()
		redeemed := app.do(http.MethodPost, "/api/support/redeem", `{"code":"`+code+`"}`)
		if redeemed.status != http.StatusOK {
			t.Fatalf("redeem: %d %s", redeemed.status, redeemed.body)
		}
		r := redeemed.json(t)
		token := str(r, "session_token")
		if !token64.MatchString(token) || str(r, "supporter") != "Olga Operator" || str(r, "session", "status") != "opened" {
			t.Fatalf("redeem answer %v", r)
		}
		if again := w.app().do(http.MethodPost, "/api/support/redeem", `{"code":"`+code+`"}`); again.status != http.StatusNotFound {
			t.Fatalf("redeemed twice: %d", again.status)
		}
		bearer := []string{"Authorization", "Bearer " + token}
		step := func(path, body string, want int) map[string]any {
			t.Helper()
			res := app.do(http.MethodPost, path, body, bearer...)
			if res.status != want {
				t.Fatalf("%s: %d %s, want %d", path, res.status, res.body, want)
			}
			return res.json(t)
		}
		step("/api/support/session/consent", `{"allowed":true}`, http.StatusConflict)
		if s := step("/api/support/session/device", `{"device_id":"423456789","hostname":"ana-laptop"}`, http.StatusOK); str(s, "session", "status") != "asking" {
			t.Fatalf("device: %v", s)
		}
		if p, _ := w.gdb.GetPeer("423456789"); p == nil || p.DeviceType != "quick_support" {
			t.Fatalf("no temporary device: %+v", p)
		}
		step("/api/support/session/password", `{"password":"too-early"}`, http.StatusConflict)
		step("/api/support/session/consent", `{"allowed":true}`, http.StatusOK)
		step("/api/support/session/password", `{"password":"Ab12-cd34"}`, http.StatusOK)

		if s := operator.do(http.MethodGet, "/api/support/sessions/"+id, "").json(t); str(s, "session", "status") != "allowed" || s["session"].(map[string]any)["password_ready"] != true {
			t.Fatalf("supporter sees %v", s)
		}
		if res := admin.do(http.MethodPost, "/api/support/sessions/"+id+"/password", `{}`); res.status != http.StatusNotFound {
			t.Fatalf("another account took the password: %d %s", res.status, res.body)
		}
		if res := admin.do(http.MethodPost, "/api/support/devices/423456789/password", `{}`); res.status != http.StatusOK || res.body != `{"success":true,"password":""}` {
			t.Fatalf("another account took the password by device: %d %s", res.status, res.body)
		}
		if pw := operator.do(http.MethodPost, "/api/support/sessions/"+id+"/password", `{}`).json(t); str(pw, "password") != "Ab12-cd34" {
			t.Fatalf("password %v", pw)
		}
		if res := operator.do(http.MethodPost, "/api/support/sessions/"+id+"/password", `{}`); res.status != http.StatusConflict {
			t.Fatalf("handed over twice: %d %s", res.status, res.body)
		}

		step("/api/support/session/end", `{}`, http.StatusOK)
		if res := app.do(http.MethodGet, "/api/support/session", "", bearer...); res.status != http.StatusUnauthorized {
			t.Fatalf("the token of an ended session: %d %s", res.status, res.body)
		}
		if s := operator.do(http.MethodGet, "/api/support/sessions/"+id, "").json(t); str(s, "session", "status") != "ended" || str(s, "session", "ended_by") != "customer" {
			t.Fatalf("after the end: %v", s)
		}
	})
}

// TestPublicStateFollowsTheLink: the page of a support link asks for its
// state and sees the app take the code, the person allow, and the end; a
// code nobody made, and a spent code without a session, stay the usual 404.
func TestPublicStateFollowsTheLink(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	code := str(w.browser("operator").do(http.MethodPost, "/api/support/sessions", `{"name":"Ana"}`).json(t), "code")
	page := w.app()
	state := func(want string) {
		t.Helper()
		res := page.do(http.MethodGet, "/api/onboard/public/"+code+"/state", "")
		if res.status != http.StatusOK || str(res.json(t), "state") != want {
			t.Fatalf("state: %d %s, want %s", res.status, res.body, want)
		}
	}
	state("waiting")
	if res := page.do(http.MethodGet, "/api/onboard/public/ZZZZZZZZ/state", ""); res.status != http.StatusNotFound {
		t.Fatalf("unknown code: %d %s", res.status, res.body)
	}

	app := w.app()
	token := str(app.do(http.MethodPost, "/api/support/redeem", `{"code":"`+code+`"}`).json(t), "session_token")
	bearer := []string{"Authorization", "Bearer " + token}
	state("opened")
	// The page data itself stays gone for a spent code
	if res := page.do(http.MethodGet, "/api/onboard/public/"+code, ""); res.status != http.StatusNotFound {
		t.Fatalf("page data of a spent code: %d", res.status)
	}
	app.do(http.MethodPost, "/api/support/session/device", `{"device_id":"423456789","hostname":"ana-laptop"}`, bearer...)
	state("opened")
	app.do(http.MethodPost, "/api/support/session/consent", `{"allowed":true}`, bearer...)
	state("allowed")
	app.do(http.MethodPost, "/api/support/session/end", `{}`, bearer...)
	state("ended")
}

// TestQuickSupportOfARevokedID: the app's device is refused at once with
// the reason, the session ends with it, and the supporter sees why and on
// which computer (L550).
func TestQuickSupportOfARevokedID(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	if err := w.blocklist.BlockID("828416401", "revoked via panel"); err != nil {
		t.Fatal(err)
	}
	operator := w.browser("operator")
	made := operator.do(http.MethodPost, "/api/support/sessions", `{"name":"Ana"}`).json(t)
	code, id := str(made, "code"), str(made, "session", "id")
	app := w.app()
	token := str(app.do(http.MethodPost, "/api/support/redeem", `{"code":"`+code+`"}`).json(t), "session_token")
	res := app.do(http.MethodPost, "/api/support/session/device", `{"device_id":"828416401","hostname":"desktop-3mu2dcg"}`, "Authorization", "Bearer "+token)
	if res.status != http.StatusForbidden || str(res.json(t), "error") != "device_refused" || str(res.json(t), "reason") != "device_revoked" {
		t.Fatalf("device: %d %s", res.status, res.body)
	}
	s := operator.do(http.MethodGet, "/api/support/sessions/"+id, "").json(t)
	if str(s, "session", "status") != "ended" || str(s, "session", "ended_by") != "refused" ||
		str(s, "session", "end_reason") != "device_revoked" || str(s, "session", "device_id") != "828416401" ||
		str(s, "session", "hostname") != "desktop-3mu2dcg" {
		t.Fatalf("the supporter sees %v", s)
	}
	if p, _ := w.gdb.GetPeer("828416401"); p != nil {
		t.Fatalf("a device was made for the revoked ID: %+v", p)
	}
}

// TestDevicePasswordNamesTheQuickSupportSession: when the server holds no
// session password (it keeps it in memory only, a restart loses it, and it
// hands it out once), the viewer still learns that the device runs this
// account's quick support session and whom it waits for, so it asks the
// person to accept instead of asking for a password (L551).
func TestDevicePasswordNamesTheQuickSupportSession(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	operator := w.browser("operator")
	made := operator.do(http.MethodPost, "/api/support/sessions", `{"name":"Ana"}`).json(t)
	app := w.app()
	token := str(app.do(http.MethodPost, "/api/support/redeem", `{"code":"`+str(made, "code")+`"}`).json(t), "session_token")
	bearer := []string{"Authorization", "Bearer " + token}
	app.do(http.MethodPost, "/api/support/session/device", `{"device_id":"423456780","hostname":"ana-laptop"}`, bearer...)
	app.do(http.MethodPost, "/api/support/session/consent", `{"allowed":true}`, bearer...)

	res := operator.do(http.MethodPost, "/api/support/devices/423456780/password", `{}`)
	if res.status != http.StatusOK || res.body != `{"success":true,"password":"","session":{"name":"Ana","status":"allowed"}}` {
		t.Fatalf("the session without its password: %d %s", res.status, res.body)
	}
	if res := w.browser("admin").do(http.MethodPost, "/api/support/devices/423456780/password", `{}`); res.body != `{"success":true,"password":""}` {
		t.Fatalf("another account sees the session: %d %s", res.status, res.body)
	}
}

// TestDevicePasswordWithoutAHandedPasswordIsEmpty: the browser viewer asks
// for a handed quick support password whenever a device asks for its
// password; a device without one is the usual case, answered with an empty
// password, not as an error (L429).
func TestDevicePasswordWithoutAHandedPasswordIsEmpty(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	operator := w.browser("operator")
	res := operator.do(http.MethodPost, "/api/support/devices/123456789/password", `{}`)
	if res.status != http.StatusOK || res.body != `{"success":true,"password":""}` {
		t.Fatalf("a device without a handed password: %d %s, want 200 with an empty password", res.status, res.body)
	}
}

func TestSessionTokenOpensOnlyTheAppRoutes(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	operator := w.browser("operator")
	code := str(operator.do(http.MethodPost, "/api/support/sessions", `{}`).json(t), "code")
	token := str(w.app().do(http.MethodPost, "/api/support/redeem", `{"code":"`+code+`"}`).json(t), "session_token")
	app := w.app()
	bearer := []string{"Authorization", "Bearer " + token}
	for _, path := range []string{"/api/support/sessions", "/api/onboard/invites", "/api/devices"} {
		if res := app.do(http.MethodGet, path, "", bearer...); res.status != http.StatusUnauthorized && res.status != http.StatusForbidden {
			t.Errorf("%s with a session token: %d %s", path, res.status, res.body)
		}
	}
	if res := app.do(http.MethodGet, "/api/support/session", "", "Authorization", "Bearer "+strings.Repeat("a", 64)); res.status != http.StatusUnauthorized {
		t.Errorf("a made-up token: %d", res.status)
	}
	if res := app.do(http.MethodGet, "/api/support/session", "", bearer...); res.status != http.StatusOK {
		t.Errorf("its own route: %d %s", res.status, res.body)
	}
}

func TestSupporterEndsAWaitingSessionAndItsCode(t *testing.T) {
	w := newWorld(t, storetest.Migrated(t))
	operator := w.browser("operator")
	made := operator.do(http.MethodPost, "/api/support/sessions", `{}`).json(t)
	code, id := str(made, "code"), str(made, "session", "id")
	if res := operator.do(http.MethodDelete, "/api/support/sessions/"+id, ""); res.status != http.StatusOK || str(res.json(t), "session", "status") != "expired" {
		t.Fatalf("end: %d %s", res.status, res.body)
	}
	if res := w.app().do(http.MethodPost, "/api/support/redeem", `{"code":"`+code+`"}`); res.status != http.StatusNotFound {
		t.Fatalf("the code of an ended session: %d %s", res.status, res.body)
	}
	if res := operator.do(http.MethodGet, "/api/support/sessions", ""); strings.Contains(res.body, id) {
		t.Fatalf("an ended session is listed as open: %s", res.body)
	}
}

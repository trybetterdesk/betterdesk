package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neodeskapp/neodesk/neodesk-server/config"
	"github.com/neodeskapp/neodesk/neodesk-server/peer"
)

// TestComputersChatWhileTheConsoleStarts: the API port listens before the
// console is up. A computer's chat asked in that moment gets 503 with a
// short Retry-After, so the client asks again in seconds, not in ten
// minutes as after a 404 (L536). 404 is only for a server without a
// console; once the console is up, it answers.
func TestComputersChatWhileTheConsoleStarts(t *testing.T) {
	srv := New(config.DefaultConfig(), testSetupDB(t), peer.NewMap(), nil, "test")
	h := srv.ListenerHandler()
	ask := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	for _, path := range []string{"/ws/chat/900100001?v=2", "/api/chat/device/files/0123456789abcdef0123456789abcdef", "/api/chat/device/helper/picture"} {
		rec := ask(path)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "5" || rec.Header().Get("X-NeoDesk-Chat") != "starting" {
			t.Errorf("%s before the console: %d %v", path, rec.Code, rec.Header())
		}
	}

	srv.SetDeviceChat(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for _, path := range []string{"/ws/chat/900100001?v=2", "/api/chat/device/helper/picture"} {
		if rec := ask(path); rec.Code != http.StatusTeapot {
			t.Errorf("%s with the console: %d", path, rec.Code)
		}
	}

	// A console that stops (the server shuts down or restarts) comes back
	srv.SetDeviceChat(nil)
	if rec := ask("/ws/chat/900100001?v=2"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("while the console stops: %d, want 503", rec.Code)
	}

	// No console at all (CONSOLE_PORT=0, or one that could not start)
	srv.NoDeviceChat()
	if rec := ask("/ws/chat/900100001?v=2"); rec.Code != http.StatusNotFound {
		t.Errorf("without a console: %d, want 404", rec.Code)
	}
	// The chat of version 1 never was on this port
	srv.SetDeviceChat(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	if rec := ask("/ws/chat/900100001"); rec.Code != http.StatusNotFound {
		t.Errorf("version 1: %d, want 404", rec.Code)
	}
}

// TestComputersTicketsGoToTheConsole: the routes of a computer's tickets
// go to the console as its chat does (A277), and nothing else below
// /api/tickets: the staff routes stay the API's.
func TestComputersTicketsGoToTheConsole(t *testing.T) {
	for path, want := range map[string]bool{
		"/api/tickets/nd":                     true,
		"/api/tickets/nd/12":                  true,
		"/api/tickets/nd/12/comments":         true,
		"/api/tickets/nd/12/read":             true,
		"/api/tickets/nd/12/attachments/7":    true,
		"/api/tickets":                        false,
		"/api/tickets/12":                     false,
		"/api/tickets/nd/":                    false,
		"/api/tickets/nd/x":                   false,
		"/api/tickets/nd/12/attachments":      false,
		"/api/tickets/nd/12/attachments/x":    false,
		"/api/tickets/nd/12/comments/3":       false,
		"/api/tickets/nd/12/delete":           false,
		"/api/tickets/attachments/7":          false,
		"/api/tickets/ndx":                    false,
		"/api/tickets/nd/12/attachments/7/xx": false,
	} {
		chat, socket := deviceChatRequest(httptest.NewRequest("GET", path, nil))
		if chat != want || socket {
			t.Errorf("%s: to the console %v (socket %v), want %v", path, chat, socket, want)
		}
	}
}

// TestTheDevicePolicyGoesToTheConsole: the receiver app asks for its
// policy (A277) and about an unattended caller (A279) at the API port,
// where it reaches its chat and tickets. Only those routes of /api/nd go
// to the console; the others stay the API's.
func TestTheDevicePolicyGoesToTheConsole(t *testing.T) {
	for path, want := range map[string]bool{
		"/api/nd/device-policy":            true,
		"/api/nd/device-policy/":           false,
		"/api/nd/device-policy/x":          false,
		"/api/nd/attestation":              false,
		"/api/nd/mgmt/connected":           false,
		"/api/nd/api/nd/device-policy":     false,
		"/api/nd/device-policyx":           false,
		"/api/nd/unattended/caller":        true,
		"/api/nd/unattended/caller/":       false,
		"/api/nd/unattended":               false,
		"/api/nd/api/nd/unattended/caller": false,
	} {
		chat, socket := deviceChatRequest(httptest.NewRequest("GET", path, nil))
		if chat != want || socket {
			t.Errorf("%s: to the console %v (socket %v), want %v", path, chat, socket, want)
		}
	}
}

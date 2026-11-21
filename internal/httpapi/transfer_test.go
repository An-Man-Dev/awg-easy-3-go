package httpapi

import (
	"awg-panel/internal/model"
	"awg-panel/internal/portable"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func transferCall(a *API, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	a.mu.Lock()
	a.limits = map[string]bucket{}
	a.global = bucket{}
	a.mu.Unlock()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "http://localhost:8881/api/transfer/"+path, bytes.NewReader(b))
	r.RemoteAddr = "198.51.100.12:12345"
	r.Header.Set("Origin", "http://localhost:8881")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func TestTransferAuthorizationAndPreviewBinding(t *testing.T) {
	a := testAPI(t, true)
	cookie := accountSession(a, model.BootstrapAccountID)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	req := transferRequest{Password: "test-password-12345", Secret: key, Mode: "key", Include: false}
	for _, tc := range []struct {
		cookie *http.Cookie
		csrf   string
		status int
	}{{nil, "test-csrf", 401}, {cookie, "wrong", 403}} {
		if w := transferCall(a, "export", req, tc.cookie, tc.csrf); w.Code != tc.status {
			t.Fatal("auth gate", w.Code)
		}
	}
	req.Password = "wrong"
	if w := transferCall(a, "export", req, cookie, "test-csrf"); w.Code != 400 {
		t.Fatal("password not checked", w.Code)
	}
	req.Password = "test-password-12345"
	w := transferCall(a, "export", req, cookie, "test-csrf")
	if w.Code != 200 {
		t.Fatal("export", w.Code, w.Body.String())
	}
	encrypted := bytes.Clone(w.Body.Bytes())
	snap, err := portable.Decrypt(encrypted, key)
	if err != nil || snap.State.Peers[0].PrivateKey != "" {
		t.Fatal("exclusion", err)
	}
	req.Archive = encrypted
	preview := func() string {
		t.Helper()
		w := transferCall(a, "preview", req, cookie, "test-csrf")
		if w.Code != 200 {
			t.Fatal("preview", w.Code, w.Body.String())
		}
		var p struct{ Ticket string }
		json.Unmarshal(w.Body.Bytes(), &p)
		if bytes.Contains(w.Body.Bytes(), []byte(snap.State.PrivateKey)) {
			t.Fatal("secret in preview")
		}
		return p.Ticket
	}
	ticket := preview()
	other := accountSession(a, model.BootstrapAccountID)
	commit := transferRequest{Archive: encrypted, Secret: key, Confirm: true, Ticket: ticket}
	if w := transferCall(a, "import", commit, other, "test-csrf"); w.Code != 409 {
		t.Fatal("ticket shared between sessions", w.Code)
	}
	commit.Archive = append(bytes.Clone(encrypted), 0)
	if w := transferCall(a, "import", commit, cookie, "test-csrf"); w.Code != 409 {
		t.Fatal("archive mismatch", w.Code)
	}
	commit.Archive = encrypted
	commit.Ticket = preview()
	a.mu.Lock()
	p := a.transfers[cookie.Value]
	p.Expires = time.Now().Add(-time.Second)
	a.transfers[cookie.Value] = p
	a.mu.Unlock()
	if w := transferCall(a, "import", commit, cookie, "test-csrf"); w.Code != 409 {
		t.Fatal("expired ticket", w.Code)
	}
	if !a.service.Store.ImportAvailable() {
		t.Fatal("rejected requests changed destination")
	}
	// Verification is required even for an already authenticated session.
	_, codes := enableHTTP(t, a, cookie)
	req.Code = ""
	if w := transferCall(a, "export", req, cookie, "test-csrf"); w.Code != 400 {
		t.Fatal("TOTP bypass", w.Code)
	}
	req.Code = codes[0]
	if w := transferCall(a, "export", req, cookie, "test-csrf"); w.Code != 200 {
		t.Fatal("recovery proof", w.Code)
	}
	if w := transferCall(a, "export", req, cookie, "test-csrf"); w.Code != 400 {
		t.Fatal("recovery replay", w.Code)
	}
}

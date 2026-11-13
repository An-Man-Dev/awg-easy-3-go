package httpapi

import (
	"bytes"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/service"
)

func testAPI(t *testing.T) *API {
	t.Helper()
	s, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, name := range []string{"index.html", "app.js", "styles.css"} {
		if err = os.WriteFile(filepath.Join(root, name), []byte("test asset"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := config.Config{Host: "vpn.example.com", PanelPort: 8881, Port: 51820, Password: "test-password-12345", WebDir: root, ExternalBind: "0.0.0.0:8881", PublicOrigin: "https://panel.example.com", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("172.30.88.1/32")}}
	a, err := New(&service.Service{State: s, Config: c, Network: &network.Network{Config: c}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}
func request(a *API, method, path, body string, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://10.8.0.1:8881"+path, strings.NewReader(body))
	r.RemoteAddr = "10.8.0.2:12345"
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func TestAuthenticationCSRFAndExports(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	if w := request(a, "GET", "/api/peers", "", nil, "", origin); w.Code != 401 {
		t.Fatal("unauthenticated list allowed")
	}
	if w := request(a, "POST", "/api/login", `{"password":"test-password-12345"}`, nil, "", "https://attacker.example"); w.Code != 403 {
		t.Fatal("cross-origin login allowed")
	}
	w := request(a, "POST", "/api/login", `{"password":"test-password-12345"}`, nil, "", origin)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("session cookie missing")
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 43200 {
		t.Fatal("unsafe session cookie")
	}
	var login struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if w = request(a, "POST", "/api/logout", "", cookie, "wrong", origin); w.Code != 403 {
		t.Fatal("invalid CSRF accepted")
	}
	id := a.service.State.Peers[0].ID
	for _, kind := range []string{"config", "link", "qr"} {
		w = request(a, "GET", "/api/peers/"+id+"/"+kind, "", cookie, "", origin)
		if w.Code != 200 {
			t.Fatalf("%s export: %d %s", kind, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("secret export is cacheable")
		}
		if kind == "qr" {
			cfg, err := png.DecodeConfig(bytes.NewReader(w.Body.Bytes()))
			if err != nil || cfg.Width != 768 {
				t.Fatalf("invalid QR PNG: %v", err)
			}
		}
	}
	w = request(a, "GET", "/api/peers", "", cookie, "", origin)
	if strings.Contains(w.Body.String(), a.service.State.Peers[0].PrivateKey) {
		t.Fatal("list leaks keys")
	}
	if w = request(a, "POST", "/api/logout", "", cookie, login.CSRF, origin); w.Code != 200 {
		t.Fatal("logout failed")
	}
	if w = request(a, "GET", "/api/peers", "", cookie, "", origin); w.Code != 401 {
		t.Fatal("session survived logout")
	}
}
func TestGuestAndUntrustedProxyHeaders(t *testing.T) {
	a := testAPI(t)
	r := httptest.NewRequest("GET", "http://10.8.0.1:8881/", nil)
	r.RemoteAddr = "10.8.0.3:1000"
	r.Header.Set("X-Forwarded-For", "10.8.0.2")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unknown/guest peer accessed panel")
	}
	r.RemoteAddr = "192.0.2.3:1000"
	if a.requestIP(r).String() != "192.0.2.3" {
		t.Fatal("untrusted forwarding header accepted")
	}
	r.RemoteAddr = "172.30.88.1:1000"
	r.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.4")
	if a.requestIP(r).String() != "198.51.100.4" {
		t.Fatal("trusted chain walked incorrectly")
	}
}
func TestLoginRateLimitAndHTTPS(t *testing.T) {
	a := testAPI(t)
	for i := 0; i < 5; i++ {
		w := request(a, "POST", "/api/login", `{"password":"wrong-password"}`, nil, "", "http://10.8.0.1:8881")
		if w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := request(a, "POST", "/api/login", `{"password":"wrong-password"}`, nil, "", "http://10.8.0.1:8881"); w.Code != 429 {
		t.Fatal("brute-force limit not enforced")
	}
	r := httptest.NewRequest("POST", "https://panel.example.com/api/login", strings.NewReader(`{"password":"test-password-12345"}`))
	r.RemoteAddr = "172.30.88.1:1"
	r.TLS = nil
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://panel.example.com")
	r.Header.Set("X-Forwarded-For", "198.51.100.2")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 || !w.Result().Cookies()[0].Secure {
		t.Fatal("trusted HTTPS did not produce a secure cookie")
	}
}
func TestStaticConfinementAndCache(t *testing.T) {
	a := testAPI(t)
	for _, path := range []string{"/../go.mod", "/%2e%2e/go.mod", "/.env", "/unknown"} {
		w := request(a, "GET", path, "", nil, "", "")
		if w.Code != 404 {
			t.Fatalf("unexpected static access: %s %d", path, w.Code)
		}
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("must-not-be-served"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.config.WebDir, "app.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(a.config.WebDir, "app.js")); err != nil {
		t.Fatal(err)
	}
	if w := request(a, "GET", "/app.js", "", nil, "", ""); w.Code != 404 {
		t.Fatal("symlink escaped static root")
	}
	w := request(a, "GET", "/", "", nil, "", "")
	etag := w.Header().Get("ETag")
	if w.Code != 200 || etag == "" || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("static cache headers missing")
	}
	r := httptest.NewRequest("GET", "http://10.8.0.1:8881/", nil)
	r.RemoteAddr = "10.8.0.2:1"
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 304 {
		t.Fatal("ETag revalidation failed")
	}
}

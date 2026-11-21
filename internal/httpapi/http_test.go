package httpapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/service"
	"awg-panel/internal/store"
)

func TestHSTSRequiresAuthenticatedHTTPSIndication(t *testing.T) {
	a := testAPI(t)
	for _, tc := range []struct {
		name, remote, forwarded string
		tls, want               bool
	}{
		{"VPN HTTP", "10.8.0.2:1234", "", false, false},
		{"forged proxy header", "198.51.100.2:1234", "https", false, false},
		{"trusted proxy HTTP", "172.30.88.1:1234", "http", false, false},
		{"trusted proxy HTTPS", "172.30.88.1:1234", "https", false, true},
		{"direct TLS", "198.51.100.2:1234", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both static content and unauthenticated API errors need the policy.
			for _, path := range []string{"/", "/api/session"} {
				r := httptest.NewRequest("GET", "http://panel.example.com"+path, nil)
				r.RemoteAddr = tc.remote
				r.Header.Set("X-Forwarded-Proto", tc.forwarded)
				if tc.tls {
					r.TLS = &tls.ConnectionState{}
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				want := ""
				if tc.want {
					want = "max-age=31536000"
				}
				if got := w.Header().Get("Strict-Transport-Security"); got != want {
					t.Fatalf("%s: HSTS %q, want %q", path, got, want)
				}
			}
		})
	}
}

func testAPI(t *testing.T, fresh ...bool) *API {
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
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err = st.Initialize(c.Password, false, model.Addresses{Revision: 1, VPNHost: c.Host, PanelOrigin: c.PublicOrigin}); err != nil {
		t.Fatal(err)
	}
	if len(fresh) == 0 {
		if err = st.Save(s); err != nil {
			t.Fatal(err)
		}
	}
	s, err = st.Load()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(&service.Service{Store: st, State: s, Config: c, Network: &network.Network{Config: c}})
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
		if kind == "link" {
			var export struct {
				Link  string `json:"link"`
				Parts int    `json:"qrParts"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &export); err != nil || export.Parts < 1 || !strings.HasPrefix(export.Link, "vpn://") {
				t.Fatal("missing QR series metadata")
			}
			var previous []byte
			for part := 0; part < export.Parts; part++ {
				frame := request(a, "GET", "/api/peers/"+id+"/qr?part="+strconv.Itoa(part), "", cookie, "", origin)
				if frame.Code != 200 || frame.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("QR part unavailable or cacheable")
				}
				if _, err := png.Decode(bytes.NewReader(frame.Body.Bytes())); err != nil || bytes.Equal(previous, frame.Body.Bytes()) {
					t.Fatal("QR part is invalid or repeats the previous frame")
				}
				previous = bytes.Clone(frame.Body.Bytes())
			}
			for _, part := range []string{"-1", "invalid", strconv.Itoa(export.Parts)} {
				if frame := request(a, "GET", "/api/peers/"+id+"/qr?part="+part, "", cookie, "", origin); frame.Code != 400 {
					t.Fatal("invalid QR part accepted")
				}
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
	// Invalid oversized passwords still consume the limiter, without coupling
	// this burst test to KDF speed or the 30-second refill interval under -race.
	body := `{"password":"` + strings.Repeat("x", 257) + `"}`
	for i := 0; i < 5; i++ {
		w := request(a, "POST", "/api/login", body, nil, "", "http://10.8.0.1:8881")
		if w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := request(a, "POST", "/api/login", body, nil, "", "http://10.8.0.1:8881"); w.Code != 429 {
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

func TestStoredAccountCredentialsAndSessionIdentity(t *testing.T) {
	original := testAPI(t)
	svc := &service.Service{State: original.service.State, Store: original.service.Store, Network: original.service.Network, Config: original.service.Config}
	svc.Config.Password = "different-bootstrap-password"
	a, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	origin := "http://10.8.0.1:8881"
	if w := request(a, "POST", "/api/login", `{"password":"different-bootstrap-password"}`, nil, "", origin); w.Code != 401 {
		t.Fatal("environment password replaced stored credentials")
	}
	w := request(a, "POST", "/api/login", `{"password":"test-password-12345"}`, nil, "", origin)
	if w.Code != 200 {
		t.Fatalf("stored password rejected: %d", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	sess := a.sessions[cookie.Value]
	if sess.AccountID != model.BootstrapAccountID {
		t.Fatal("session not bound to initial account")
	}
	sess.AccountID = "missing-account"
	a.sessions[cookie.Value] = sess
	if w = request(a, "GET", "/api/peers", "", cookie, "", origin); w.Code != 401 {
		t.Fatal("session for missing account retained access")
	}
}

func TestSettingsAuthorizationPersistenceAndExportVersion(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	if w := request(a, "GET", "/api/settings", "", nil, "", origin); w.Code != 401 {
		t.Fatal("settings disclosed without login")
	}
	w := request(a, "POST", "/api/login", `{"password":"test-password-12345"}`, nil, "", origin)
	cookie := w.Result().Cookies()[0]
	var login struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	w = request(a, "GET", "/api/settings", "", cookie, "", origin)
	var settings model.Settings
	if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	id := a.service.List()[0].ID
	old := request(a, "GET", "/api/peers/"+id+"/link", "", cookie, "", origin)
	var link struct {
		Version string `json:"version"`
	}
	json.Unmarshal(old.Body.Bytes(), &link)
	settings.ServerName = "My network"
	settings.Client.MTU = 1400
	settings.Client.PersistentKeepalive = 0
	settings.Client.DNS = []string{"9.9.9.9"}
	settings.Client.AllowedIPs = []string{"10.8.0.0/24"}
	body, _ := json.Marshal(settings)
	if w = request(a, "PUT", "/api/settings", string(body), cookie, "bad", origin); w.Code != 403 {
		t.Fatal("settings changed without CSRF")
	}
	if w = request(a, "PUT", "/api/settings", string(body), cookie, login.CSRF, origin); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if w = request(a, "PUT", "/api/settings", string(body), cookie, login.CSRF, origin); w.Code != 409 {
		t.Fatal("stale edit accepted")
	}
	if w = request(a, "GET", "/api/peers/"+id+"/qr?version="+link.Version, "", cookie, "", origin); w.Code != 409 {
		t.Fatal("mixed-version QR allowed")
	}
	if w = request(a, "GET", "/api/peers/"+id+"/config?version="+link.Version, "", cookie, "", origin); w.Code != 409 {
		t.Fatal("mixed-version config allowed")
	}
	w = request(a, "GET", "/api/peers/"+id+"/config", "", cookie, "", origin)
	for _, value := range []string{"MTU = 1400", "PersistentKeepalive = 0", "DNS = 9.9.9.9", "AllowedIPs = 10.8.0.0/24"} {
		if !strings.Contains(w.Body.String(), value) {
			t.Fatal("existing device export did not use global settings")
		}
	}
	persisted, err := a.service.Store.Load()
	if err != nil || persisted.Settings.ServerName != "My network" {
		t.Fatal("settings were not committed")
	}
	settings.Revision++
	settings.Client.DNS = []string{"bad\nDNS"}
	body, _ = json.Marshal(settings)
	if w = request(a, "PUT", "/api/settings", string(body), cookie, login.CSRF, origin); w.Code != 400 {
		t.Fatal("invalid settings accepted")
	}
	if w = request(a, "PUT", "/api/settings", `{"host":"changed.example"}`, cookie, login.CSRF, origin); w.Code != 400 {
		t.Fatal("out-of-scope settings accepted")
	}
	if a.service.Settings().Revision != 2 {
		t.Fatal("failed request modified settings")
	}
}

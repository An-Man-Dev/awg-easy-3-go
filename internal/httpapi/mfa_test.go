package httpapi

import (
	"awg-panel/internal/model"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func totpNow(secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(counter[:])
	sum := m.Sum(nil)
	o := sum[19] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[o:o+4])&0x7fffffff)%1000000)
}
func mfaRequest(a *API, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	// Isolate per-account second-factor throttling from the existing IP limiter.
	a.mu.Lock()
	a.limits = map[string]bucket{}
	a.global = bucket{}
	a.mu.Unlock()
	encoded, _ := json.Marshal(body)
	return request(a, method, path, string(encoded), cookie, "test-csrf", "http://10.8.0.1:8881")
}
func responseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	t.Fatalf("missing %s cookie (HTTP %d)", name, w.Code)
	return nil
}
func enableHTTP(t *testing.T, a *API, cookie *http.Cookie) (string, []string) {
	t.Helper()
	w := mfaRequest(a, "POST", "/api/account/totp/setup", map[string]any{"password": "test-password-12345"}, cookie)
	if w.Code != 200 {
		t.Fatal("setup", w.Code)
	}
	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
		QR     string `json:"qr"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil || setup.QR == "" || setup.URI == "" {
		t.Fatal("incomplete setup")
	}
	status, _ := a.service.Store.MFAStatus(model.BootstrapAccountID)
	if status.Enabled {
		t.Fatal("enabled before confirmation")
	}
	w = mfaRequest(a, "POST", "/api/account/totp/confirm", map[string]any{"code": totpNow(setup.Secret)}, cookie)
	if w.Code != 200 {
		t.Fatal("confirm", w.Code)
	}
	var result struct {
		Codes []string `json:"recoveryCodes"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Codes) != 10 {
		t.Fatal("recovery set missing")
	}
	return setup.Secret, result.Codes
}
func TestMFALoginChallengeAndPasswordRevocation(t *testing.T) {
	a := testAPI(t)
	root := accountSession(a, model.BootstrapAccountID)
	other := accountSession(a, model.BootstrapAccountID)
	_, codes := enableHTTP(t, a, root)
	if w := mfaRequest(a, "GET", "/api/session", nil, other); w.Code != 401 {
		t.Fatal("old session survived enrollment")
	}
	if w := mfaRequest(a, "GET", "/api/session", nil, root); w.Code != 200 {
		t.Fatal("confirming session lost before saving codes")
	}
	w := mfaRequest(a, "POST", "/api/login", map[string]any{"login": "admin", "password": "test-password-12345"}, nil)
	if w.Code != 200 {
		t.Fatal("password stage", w.Code)
	}
	challenge := responseCookie(t, w, "awg_challenge")
	for _, c := range w.Result().Cookies() {
		if c.Name == "awg_session" && c.Value != "" {
			t.Fatal("full session issued before MFA")
		}
	}
	if w = mfaRequest(a, "GET", "/api/peers", nil, challenge); w.Code != 401 {
		t.Fatal("challenge used as session")
	}
	if w = mfaRequest(a, "POST", "/api/login/verify", map[string]any{"code": "invalid"}, challenge); w.Code != 401 {
		t.Fatal("invalid proof accepted")
	}
	w = mfaRequest(a, "POST", "/api/login/verify", map[string]any{"code": codes[0]}, challenge)
	if w.Code != 200 {
		t.Fatal("recovery login", w.Code)
	}
	full := responseCookie(t, w, "awg_session")
	if w = mfaRequest(a, "GET", "/api/session", nil, full); w.Code != 200 {
		t.Fatal("verified session rejected")
	}
	if w = mfaRequest(a, "POST", "/api/login/verify", map[string]any{"code": codes[1]}, challenge); w.Code != 401 {
		t.Fatal("challenge reused")
	}
	status, _ := a.service.Store.MFAStatus(model.BootstrapAccountID)
	if status.RecoveryRemaining != 9 {
		t.Fatal("stale challenge consumed another code")
	}
	w = mfaRequest(a, "POST", "/api/login", map[string]any{"password": "test-password-12345"}, nil)
	pending := responseCookie(t, w, "awg_challenge")
	body := map[string]any{"currentPassword": "test-password-12345", "newPassword": "changed-with-mfa-12345", "confirmPassword": "changed-with-mfa-12345"}
	if w = mfaRequest(a, "PUT", "/api/account/password", body, root); w.Code != 400 {
		t.Fatal("password changed without MFA", w.Code)
	}
	body["code"] = codes[1]
	if w = mfaRequest(a, "PUT", "/api/account/password", body, root); w.Code != 200 {
		t.Fatal("password with recovery", w.Code)
	}
	if w = mfaRequest(a, "POST", "/api/login/verify", map[string]any{"code": codes[2]}, pending); w.Code != 401 {
		t.Fatal("pre-reset challenge retained access")
	}
	if w = mfaRequest(a, "GET", "/api/session", nil, full); w.Code != 401 {
		t.Fatal("password reset did not revoke sessions")
	}
}
func TestMFAExpiryCSRFAndSessionRevocation(t *testing.T) {
	a := testAPI(t)
	root := accountSession(a, model.BootstrapAccountID)
	_, codes := enableHTTP(t, a, root)
	w := mfaRequest(a, "POST", "/api/login", map[string]any{"password": "test-password-12345"}, nil)
	challenge := responseCookie(t, w, "awg_challenge")
	c := a.challenges[challenge.Value]
	c.Expires = time.Now().Add(-time.Minute)
	a.challenges[challenge.Value] = c
	if w = mfaRequest(a, "POST", "/api/login/verify", map[string]any{"code": codes[0]}, challenge); w.Code != 401 {
		t.Fatal("expired challenge accepted")
	}
	w = request(a, "DELETE", "/api/account/totp", `{"password":"test-password-12345","confirm":true}`, root, "", "http://10.8.0.1:8881")
	if w.Code != 403 {
		t.Fatal("MFA CSRF bypass")
	}
	if w = mfaRequest(a, "DELETE", "/api/account/sessions", nil, root); w.Code != 200 {
		t.Fatal("session revocation failed")
	}
	if w = mfaRequest(a, "GET", "/api/session", nil, root); w.Code != 401 {
		t.Fatal("self session survived revoke")
	}
	status, _ := a.service.Store.MFAStatus(model.BootstrapAccountID)
	if !status.Enabled || status.RecoveryRemaining != 10 {
		t.Fatal("failed requests changed MFA")
	}
}
func TestAdminResetMFAAuthorizationAndPendingChallenges(t *testing.T) {
	a := testAPI(t)
	manager := accountFixture(t, a, "manager", "admin", "")
	other := accountFixture(t, a, "other", "admin", "")
	user := accountFixture(t, a, "member", "user", manager.ID)
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	codes, err := a.service.Store.EnableMFA(user.ID, user.Revision, secret, "287082", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	owner := accountSession(a, user.ID)
	admin := accountSession(a, manager.ID)
	foreign := accountSession(a, other.ID)
	w := mfaRequest(a, "POST", "/api/login", map[string]any{"login": "member", "password": "account-test-password"}, nil)
	pending := responseCookie(t, w, "awg_challenge")
	body := map[string]any{"password": "account-test-password", "confirm": true}
	path := "/api/accounts/" + user.ID + "/totp"
	if w = mfaRequest(a, "DELETE", path, body, foreign); w.Code != 404 {
		t.Fatal("foreign manager reset MFA", w.Code)
	}
	if w = mfaRequest(a, "DELETE", path, body, owner); w.Code != 404 {
		t.Fatal("user used administrative endpoint", w.Code)
	}
	if w = mfaRequest(a, "DELETE", path, body, admin); w.Code != 200 {
		t.Fatal("manager reset failed", w.Code)
	}
	if w = mfaRequest(a, "GET", "/api/session", nil, owner); w.Code != 401 {
		t.Fatal("target session survived admin reset")
	}
	if w = mfaRequest(a, "POST", "/api/login/verify", map[string]any{"code": codes[0]}, pending); w.Code != 401 {
		t.Fatal("target challenge survived admin reset")
	}
	status, _ := a.service.Store.MFAStatus(user.ID)
	if status.Enabled || status.RecoveryRemaining != 0 {
		t.Fatal("reset left recovery codes")
	}
	if w = mfaRequest(a, "POST", "/api/login", map[string]any{"login": "member", "password": "account-test-password"}, nil); w.Code != 200 {
		t.Fatal("target password changed")
	}
	responseCookie(t, w, "awg_session")
}

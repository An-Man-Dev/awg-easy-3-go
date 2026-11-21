package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestPasswordChangeRevokesAllSessions(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	login := func(password string) (*http.Cookie, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"password": password})
		w := request(a, "POST", "/api/login", string(body), nil, "", origin)
		if w.Code != 200 {
			t.Fatalf("login: %d", w.Code)
		}
		var data struct {
			CSRF string `json:"csrf"`
		}
		json.Unmarshal(w.Body.Bytes(), &data)
		return w.Result().Cookies()[0], data.CSRF
	}
	first, csrf := login("test-password-12345")
	second, _ := login("test-password-12345")
	const good = `{"currentPassword":"test-password-12345","newPassword":"replacement-password-123","confirmPassword":"replacement-password-123"}`
	for _, tc := range []struct {
		cookie       *http.Cookie
		csrf, origin string
		want         int
	}{{nil, "", origin, 401}, {first, "", origin, 403}, {first, csrf, "https://evil.example", 403}} {
		if w := request(a, "PUT", "/api/account/password", good, tc.cookie, tc.csrf, tc.origin); w.Code != tc.want {
			t.Fatalf("authorization: got %d want %d", w.Code, tc.want)
		}
	}
	bad := `{"currentPassword":"incorrect-password","newPassword":"replacement-password-123","confirmPassword":"replacement-password-123"}`
	if w := request(a, "PUT", "/api/account/password", bad, first, csrf, origin); w.Code != 400 {
		t.Fatal("incorrect current password accepted")
	}
	if w := request(a, "GET", "/api/session", "", first, "", origin); w.Code != 200 {
		t.Fatal("failed change revoked session")
	}
	if w := request(a, "PUT", "/api/account/password", good, first, csrf, origin); w.Code != 200 {
		t.Fatalf("change: %d", w.Code)
	}
	for _, cookie := range []*http.Cookie{first, second} {
		if w := request(a, "GET", "/api/session", "", cookie, "", origin); w.Code != 401 {
			t.Fatal("old session survived")
		}
	}
	a.mu.Lock()
	a.limits = map[string]bucket{}
	a.global = bucket{}
	a.mu.Unlock()
	if w := request(a, "POST", "/api/login", `{"password":"test-password-12345"}`, nil, "", origin); w.Code != 401 {
		t.Fatal("old password accepted")
	}
	login("replacement-password-123")
	// A password change cannot overlap password verification and session issuance.
	a.loginGate <- struct{}{}
	if w := request(a, "POST", "/api/login", `{"password":"replacement-password-123"}`, nil, "", origin); w.Code != 429 {
		t.Fatal("login ignored authentication gate")
	}
	<-a.loginGate
}

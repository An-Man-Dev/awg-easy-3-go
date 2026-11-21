package httpapi

import (
	"encoding/json"
	"testing"
)

func TestAddressesAuthorizationValidationAndOrigins(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	if w := request(a, "GET", "/api/addresses", "", nil, "", origin); w.Code != 401 {
		t.Fatal("unauthenticated addresses exposed")
	}
	w := request(a, "POST", "/api/login", `{"password":"test-password-12345"}`, nil, "", origin)
	cookie := w.Result().Cookies()[0]
	var login struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	body := `{"revision":1,"vpnHost":"192.0.2.2","panelOrigin":"https://panel.example"}`
	if w = request(a, "PUT", "/api/addresses", body, cookie, "", origin); w.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	body = `{"revision":1,"vpnHost":"192.0.2.2","panelOrigin":"https://panel.example/"}`
	if w = request(a, "PUT", "/api/addresses", body, cookie, login.CSRF, origin); w.Code != 400 {
		t.Fatal("invalid origin accepted")
	}
	body = `{"revision":2,"vpnHost":"192.0.2.2","panelOrigin":"https://panel.example"}`
	if w = request(a, "PUT", "/api/addresses", body, cookie, login.CSRF, origin); w.Code != 409 {
		t.Fatal("stale addresses accepted")
	}
	a.config.Host = "new.example"
	a.config.PublicOrigin = "https://newpanel.example"
	a.setOrigins()
	if a.origins["https://panel.example.com"] || a.origins["http://vpn.example.com:8881"] {
		t.Fatal("old origins retained")
	}
	if !a.origins["https://newpanel.example"] || !a.origins[origin] {
		t.Fatal("new or recovery origin missing")
	}
}

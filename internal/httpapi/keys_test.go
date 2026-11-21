package httpapi

import (
	"encoding/json"
	"testing"
)

func TestKeyPolicyAuthorizationAndPurgeConfirmation(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	if w := request(a, "GET", "/api/key-policy", "", nil, "", origin); w.Code != 401 {
		t.Fatal("unauthenticated key policy")
	}
	w := request(a, "POST", "/api/login", `{"password":"test-password-12345"}`, nil, "", origin)
	cookie := w.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(w.Body.Bytes(), &session)
	if w = request(a, "PUT", "/api/key-policy", `{"revision":1,"retain":false}`, cookie, "", origin); w.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	w = request(a, "PUT", "/api/key-policy", `{"revision":1,"retain":false}`, cookie, session.CSRF, origin)
	if w.Code != 200 {
		t.Fatal("policy update failed")
	}
	var preview struct {
		Revision      int64  `json:"revision"`
		DeleteVersion string `json:"deleteVersion"`
	}
	json.Unmarshal(w.Body.Bytes(), &preview)
	if w = request(a, "DELETE", "/api/keys/stored", `{"confirm":false}`, cookie, session.CSRF, origin); w.Code != 400 {
		t.Fatal("unconfirmed purge")
	}
	peer := a.service.List()[0]
	body, _ := json.Marshal(map[string]any{"keyVersion": peer.KeyVersion, "confirm": true})
	if w = request(a, "POST", "/api/peers/"+peer.ID+"/reissue", string(body), cookie, session.CSRF, origin); w.Code != 409 {
		t.Fatal("own VPN device reissued before delivery")
	}
	body, _ = json.Marshal(map[string]any{"revision": preview.Revision, "deleteVersion": preview.DeleteVersion, "confirm": true})
	if w = request(a, "DELETE", "/api/keys/stored", string(body), cookie, session.CSRF, origin); w.Code != 200 {
		t.Fatal("confirmed purge failed")
	}
	for _, kind := range []string{"config", "link", "qr"} {
		if w = request(a, "GET", "/api/peers/"+peer.ID+"/"+kind, "", cookie, "", origin); w.Code != 404 {
			t.Fatal("purged key still exportable")
		}
	}
}

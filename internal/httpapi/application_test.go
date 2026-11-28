package httpapi

import (
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"testing"
)

func TestNetworkStatusAndRetryAuthorization(t *testing.T) {
	a := testAPI(t, true)
	origin := "http://localhost:8881"
	if w := request(a, "GET", "/api/network-status", "", nil, "", origin); w.Code != 401 {
		t.Fatal("anonymous status", w.Code)
	}
	root := accountSession(a, model.BootstrapAccountID)
	if w := request(a, "GET", "/api/network-status", "", root, "", origin); w.Code != 200 {
		t.Fatal("status", w.Code)
	}
	if w := request(a, "POST", "/api/network-reapply", `{"confirm":true}`, root, "", origin); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	if w := request(a, "POST", "/api/network-reapply", `{"confirm":false}`, root, "test-csrf", origin); w.Code != 400 {
		t.Fatal("confirmation bypass", w.Code)
	}
	admin, err := a.service.Store.WriteAccount(model.BootstrapAccountID, store.Account{Login: "status-admin", Role: "admin", Enabled: true}, "test-password-12345", false)
	if err != nil {
		t.Fatal(err)
	}
	cookie := accountSession(a, admin.ID)
	if w := request(a, "GET", "/api/network-status", "", cookie, "", origin); w.Code != 403 {
		t.Fatal("admin status access", w.Code)
	}
	if w := request(a, "POST", "/api/network-reapply", `{"confirm":true}`, cookie, "test-csrf", origin); w.Code != 403 {
		t.Fatal("admin retry access", w.Code)
	}
}

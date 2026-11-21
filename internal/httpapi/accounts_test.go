package httpapi

import (
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func accountFixture(t *testing.T, a *API, login, role, manager string) store.Account {
	t.Helper()
	v, err := a.service.Store.WriteAccount(model.BootstrapAccountID, store.Account{Login: login, Role: role, Enabled: true, ManagerID: manager}, "account-test-password", false)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func accountSession(a *API, id string) *http.Cookie {
	token := model.Random(32)
	a.sessions[token] = session{AccountID: id, CSRF: "test-csrf", Expires: time.Now().Add(time.Hour)}
	return &http.Cookie{Name: "awg_session", Value: token}
}
func accountBody(a store.Account) string {
	b, _ := json.Marshal(map[string]any{"login": a.Login, "role": a.Role, "managerId": a.ManagerID, "enabled": a.Enabled, "revision": a.Revision})
	return string(b)
}
func TestAccountsScopeAndDeviceExports(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	admin1 := accountFixture(t, a, "manager1", "admin", "")
	admin2 := accountFixture(t, a, "manager2", "admin", "")
	user1 := accountFixture(t, a, "user1", "user", admin1.ID)
	user2 := accountFixture(t, a, "user2", "user", admin2.ID)
	for i, owner := range []store.Account{admin1, admin2, user1, user2} {
		p, err := model.NewPeer(owner.Login, "home", 3+i, owner.ID)
		if err != nil {
			t.Fatal(err)
		}
		a.service.State.Peers = append(a.service.State.Peers, p)
	}
	if err := a.service.Store.Save(a.service.State); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []store.Account{admin1, admin2, user1, user2} {
		cookie := accountSession(a, actor.ID)
		got := request(a, "GET", "/api/accounts", "", cookie, "", origin)
		if got.Code != 200 {
			t.Fatal(got.Code)
		}
		if strings.Contains(got.Body.String(), "password") || strings.Contains(got.Body.String(), "pbkdf2") {
			t.Fatal("credential hash disclosed")
		}
		var accounts []store.Account
		json.Unmarshal(got.Body.Bytes(), &accounts)
		count := 1
		if actor.Role == "admin" {
			count = 2
		}
		if len(accounts) != count {
			t.Fatal("account scope incorrect")
		}
		got = request(a, "GET", "/api/peers", "", cookie, "", origin)
		var peers []struct {
			OwnerID string `json:"ownerId"`
		}
		json.Unmarshal(got.Body.Bytes(), &peers)
		if len(peers) != count {
			t.Fatal("device scope incorrect")
		}
		for _, p := range a.service.State.Peers {
			owner, _ := a.service.Store.Account(p.OwnerID)
			current, _ := a.service.Store.Account(actor.ID)
			allowed := current.CanManage(owner)
			for _, kind := range []string{"config", "link", "qr"} {
				w := request(a, "GET", "/api/peers/"+p.ID+"/"+kind, "", cookie, "", origin)
				want := 404
				if allowed {
					want = 200
				}
				if w.Code != want {
					t.Fatalf("%s export %s: %d", actor.Login, kind, w.Code)
				}
			}
			if !allowed {
				for _, tc := range []struct{ method, suffix, body string }{{"PATCH", "", `{"enabled":false}`}, {"DELETE", "", ""}, {"POST", "/reissue", `{"confirm":true,"keyVersion":"anything"}`}} {
					w := request(a, tc.method, "/api/peers/"+p.ID+tc.suffix, tc.body, cookie, "test-csrf", origin)
					if w.Code != 404 {
						t.Fatalf("cross-owner %s allowed: %d", tc.method, w.Code)
					}
				}
			}
		}
		for _, path := range []string{"/api/settings", "/api/addresses", "/api/key-policy", "/api/keys/stored", "/api/audit"} {
			for _, verb := range []string{"GET", "PUT", "DELETE"} {
				if w := request(a, verb, path, `{}`, cookie, "test-csrf", origin); w.Code != 403 {
					t.Fatal("global access allowed", actor.Role, path, verb, w.Code)
				}
			}
		}
		w := request(a, "POST", "/api/peers", `{"ownerId":"`+model.BootstrapAccountID+`","name":"foreign","group":"home"}`, cookie, "test-csrf", origin)
		if w.Code != 400 {
			t.Fatal("foreign issuance allowed", w.Code)
		}
	}
	if len(a.service.State.Peers) != 5 {
		t.Fatal("unauthorized request changed devices")
	}
}
func TestAccountChangesTransferRevocationAndRootProtection(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	root := accountSession(a, model.BootstrapAccountID)
	admin1 := accountFixture(t, a, "manager1", "admin", "")
	admin2 := accountFixture(t, a, "manager2", "admin", "")
	user := accountFixture(t, a, "user1", "user", admin1.ID)
	c1, c2, cu := accountSession(a, admin1.ID), accountSession(a, admin2.ID), accountSession(a, user.ID)
	w := request(a, "PUT", "/api/accounts/"+user.ID, accountBody(user), c2, "test-csrf", origin)
	if w.Code != 404 {
		t.Fatal("foreign account edit allowed", w.Code)
	}
	w = request(a, "PUT", "/api/accounts/"+user.ID, accountBody(user), cu, "test-csrf", origin)
	if w.Code != 403 {
		t.Fatal("user promoted own account", w.Code)
	}
	// An admin cannot promote users or transfer them out of its management scope.
	promoted := user
	promoted.Role = "admin"
	promoted.ManagerID = ""
	if w = request(a, "PUT", "/api/accounts/"+user.ID, accountBody(promoted), c1, "test-csrf", origin); w.Code != 400 {
		t.Fatal("role change allowed", w.Code)
	}
	transferred := user
	transferred.ManagerID = admin2.ID
	if w = request(a, "PUT", "/api/accounts/"+user.ID, accountBody(transferred), c1, "test-csrf", origin); w.Code != 404 {
		t.Fatal("admin transfer allowed", w.Code)
	}
	if w = request(a, "PUT", "/api/accounts/"+user.ID, accountBody(transferred), root, "", origin); w.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	w = request(a, "PUT", "/api/accounts/"+user.ID, accountBody(transferred), root, "test-csrf", origin)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(a, "GET", "/api/session", "", cu, "", origin); w.Code != 401 {
		t.Fatal("transfer retained user session")
	}
	if w = request(a, "PUT", "/api/accounts/"+user.ID, accountBody(transferred), root, "test-csrf", origin); w.Code != 409 {
		t.Fatal("stale update allowed")
	}
	if w = request(a, "PUT", "/api/accounts/"+user.ID, accountBody(transferred), c1, "test-csrf", origin); w.Code != 404 {
		t.Fatal("old admin retained control")
	}
	user, _ = a.service.Store.Account(user.ID)
	cu = accountSession(a, user.ID)
	admin2.Enabled = false
	w = request(a, "PUT", "/api/accounts/"+admin2.ID, accountBody(admin2), root, "test-csrf", origin)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, c := range []*http.Cookie{c2, cu} {
		if w = request(a, "GET", "/api/session", "", c, "", origin); w.Code != 401 {
			t.Fatal("blocked session survived")
		}
	}
	for _, login := range []string{"manager2", "user1"} {
		if w = request(a, "POST", "/api/login", `{"login":"`+login+`","password":"account-test-password"}`, nil, "", origin); w.Code != 401 {
			t.Fatal("blocked account logged in", w.Code)
		}
	}
	admin2, _ = a.service.Store.Account(admin2.ID)
	admin2.Enabled = true
	if w = request(a, "PUT", "/api/accounts/"+admin2.ID, accountBody(admin2), root, "test-csrf", origin); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request(a, "GET", "/api/session", "", cu, "", origin); w.Code != 401 {
		t.Fatal("unblock resurrected session")
	}
	if w = request(a, "POST", "/api/login", `{"login":"user1","password":"account-test-password"}`, nil, "", origin); w.Code != 200 {
		t.Fatal("user cannot log in after unblock", w.Code)
	}
	initial, _ := a.service.Store.Account(model.BootstrapAccountID)
	initial.Enabled = false
	if w = request(a, "PUT", "/api/accounts/"+initial.ID, accountBody(initial), root, "test-csrf", origin); w.Code != 400 {
		t.Fatal("root blocked")
	}
	if w = request(a, "DELETE", "/api/accounts/"+initial.ID, `{"revision":1,"confirm":true}`, root, "test-csrf", origin); w.Code != 400 {
		t.Fatal("root deleted")
	}
	if w = request(a, "DELETE", "/api/accounts/"+admin2.ID, `{"revision":3,"confirm":true}`, root, "test-csrf", origin); w.Code != 400 {
		t.Fatal("admin with subordinate removed")
	}
	w = request(a, "GET", "/api/audit", "", root, "", origin)
	if w.Code != 200 || strings.Contains(w.Body.String(), "account-test-password") || !strings.Contains(w.Body.String(), "account.update") {
		t.Fatal("invalid audit")
	}
}

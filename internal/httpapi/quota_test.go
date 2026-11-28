package httpapi

import (
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"encoding/json"
	"fmt"
	"testing"
)

func TestDeviceQuotaDefaultsPermissionsAndIssuance(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	root := accountSession(a, model.BootstrapAccountID)
	create := func(actorID, login, role, manager string) store.Account {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"login": login, "role": role, "managerId": manager, "enabled": true, "password": "quota-test-password"})
		w := request(a, "POST", "/api/accounts", string(body), accountSession(a, actorID), "test-csrf", origin)
		if w.Code != 201 {
			t.Fatal("create", w.Code, w.Body.String())
		}
		var result store.Account
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.DeviceLimit != 10 {
			t.Fatal("default quota", result.DeviceLimit)
		}
		return result
	}
	admin := create(model.BootstrapAccountID, "quota-manager", "admin", "")
	user := create(admin.ID, "quota-user", "user", admin.ID)
	edit := func(actorID string, target store.Account, limit int) int {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"login": target.Login, "role": target.Role, "enabled": true, "managerId": target.ManagerID, "revision": target.Revision, "deviceLimit": limit})
		return request(a, "PUT", "/api/accounts/"+target.ID, string(body), accountSession(a, actorID), "test-csrf", origin).Code
	}
	for _, target := range []store.Account{admin, user} {
		if code := edit(admin.ID, target, 11); code != 404 {
			t.Fatal("admin changed quota", code)
		}
	}
	if code := edit(model.BootstrapAccountID, user, 1); code != 200 {
		t.Fatal("root quota", code)
	}
	issue := func(owner string) int {
		t.Helper()
		body := fmt.Sprintf(`{"name":"Quota guest","group":"guest","ownerId":%q}`, owner)
		w := request(a, "POST", "/api/peers", body, root, "test-csrf", origin)
		return w.Code
	}
	// Seed a committed device without applying host networking in a unit test.
	peer, err := model.NewPeer("Quota guest", "guest", 3, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	state := a.service.State
	state.Peers = append(append([]model.Peer{}, state.Peers...), peer)
	if err = a.service.Store.Save(state); err != nil {
		t.Fatal(err)
	}
	a.service.State = state
	count := len(state.Peers)
	if code := issue(user.ID); code != 400 {
		t.Fatal("quota bypass", code)
	}
	if len(a.service.State.Peers) != count {
		t.Fatal("rejected issuance changed state")
	}
	manager, _ := a.service.Store.Account(admin.ID)
	if manager.DeviceCount != 0 {
		t.Fatal("subordinate consumed manager quota")
	}
	user, _ = a.service.Store.Account(user.ID)
	if user.DeviceCount != 1 {
		t.Fatal("device count", user.DeviceCount)
	}
	if code := edit(model.BootstrapAccountID, user, 0); code != 200 {
		t.Fatal("lower quota", code)
	}
	user, _ = a.service.Store.Account(user.ID)
	if user.DeviceCount != 1 || user.DeviceLimit != 0 {
		t.Fatal("lowering quota removed a device")
	}
	state.Peers[1].Enabled = false
	if err = a.service.Store.Save(state); err != nil {
		t.Fatal("disable above quota", err)
	}
	a.service.State = state
	if code := issue(user.ID); code != 400 {
		t.Fatal("disabled device bypass", code)
	}
	state.Peers = state.Peers[:1]
	if err = a.service.Store.Save(state); err != nil {
		t.Fatal("delete above quota", err)
	}
	a.service.State = state
	if code := issue(user.ID); code != 400 {
		t.Fatal("zero quota bypass", code)
	}
	user, _ = a.service.Store.Account(user.ID)
	if code := edit(model.BootstrapAccountID, user, 1); code != 200 {
		t.Fatal("raise quota", code)
	}
	state.Peers = append(state.Peers, peer)
	if err = a.service.Store.Save(state); err != nil {
		t.Fatal("freed quota not reusable", err)
	}
	// Root devices are exempt from account quotas (the global address pool still applies).
	for slot := 4; slot < 15; slot++ {
		p, e := model.NewPeer("Root guest", "guest", slot, model.BootstrapAccountID)
		if e != nil {
			t.Fatal(e)
		}
		state.Peers = append(state.Peers, p)
	}
	if err = a.service.Store.Save(state); err != nil {
		t.Fatal("root constrained", err)
	}
}

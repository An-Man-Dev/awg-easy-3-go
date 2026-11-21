package httpapi

import (
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"encoding/json"
	"strings"
	"testing"
)

func TestAccountNoteVisibilityAndTransfer(t *testing.T) {
	a := testAPI(t)
	origin := "http://10.8.0.1:8881"
	first := accountFixture(t, a, "first", "admin", "")
	second := accountFixture(t, a, "second", "admin", "")
	member := accountFixture(t, a, "member", "user", first.ID)
	member.Note = "Private contact\n<svg onload=alert(1)>"
	var err error
	member, err = a.service.Store.WriteAccount(first.ID, member, "", false)
	if err != nil {
		t.Fatal(err)
	}
	check := func(id string, want bool) {
		t.Helper()
		w := request(a, "GET", "/api/accounts", "", accountSession(a, id), "", origin)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		if strings.Contains(w.Body.String(), "Private contact") != want {
			t.Fatal("note visibility", id)
		}
	}
	check(model.BootstrapAccountID, true)
	check(first.ID, true)
	check(second.ID, false)
	check(member.ID, false)
	body := func(v store.Account) string {
		b, _ := json.Marshal(map[string]any{"login": v.Login, "role": v.Role, "managerId": v.ManagerID, "enabled": v.Enabled, "revision": v.Revision, "note": v.Note})
		return string(b)
	}
	if w := request(a, "PUT", "/api/accounts/"+member.ID, body(member), accountSession(a, member.ID), "test-csrf", origin); w.Code != 403 {
		t.Fatal("user wrote note", w.Code)
	}
	if w := request(a, "PUT", "/api/accounts/"+member.ID, body(member), accountSession(a, second.ID), "test-csrf", origin); w.Code != 404 {
		t.Fatal("foreign manager wrote note", w.Code)
	}
	member.ManagerID = second.ID
	if w := request(a, "PUT", "/api/accounts/"+member.ID, body(member), accountSession(a, model.BootstrapAccountID), "test-csrf", origin); w.Code != 200 {
		t.Fatal("transfer", w.Code, w.Body.String())
	}
	check(first.ID, false)
	check(second.ID, true)
	check(member.ID, false)
	member, err = a.service.Store.Account(member.ID)
	if err != nil {
		t.Fatal(err)
	}
	member.Note = strings.Repeat("x", 2001)
	if w := request(a, "PUT", "/api/accounts/"+member.ID, body(member), accountSession(a, second.ID), "test-csrf", origin); w.Code != 400 {
		t.Fatal("oversized note", w.Code)
	}
	first.Note = "Superadmin-only note"
	first, err = a.service.Store.WriteAccount(model.BootstrapAccountID, first, "", false)
	if err != nil {
		t.Fatal(err)
	}
	first.Note = ""
	first.Login = "first-renamed"
	w := request(a, "PUT", "/api/accounts/"+first.ID, body(first), accountSession(a, first.ID), "test-csrf", origin)
	if w.Code != 200 || strings.Contains(w.Body.String(), "Superadmin-only") {
		t.Fatal("self edit leaked note", w.Code)
	}
	saved, err := a.service.Store.Account(first.ID)
	if err != nil || saved.Note != "Superadmin-only note" {
		t.Fatal("hidden note lost", err)
	}
}

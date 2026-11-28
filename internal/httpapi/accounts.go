package httpapi

import (
	"awg-panel/internal/model"
	"awg-panel/internal/service"
	"awg-panel/internal/store"
	"errors"
	"net/http"
	"strings"
)

func (a *API) accounts(w http.ResponseWriter, r *http.Request, sess session) {
	if strings.HasSuffix(r.URL.Path, "/totp") && r.Method == "DELETE" {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/accounts/"), "/totp")
		if id == "" || strings.Contains(id, "/") {
			problem(w, 404, "Account not found")
			return
		}
		a.adminResetMFA(w, r, sess, id)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/sessions") && r.Method == "DELETE" {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/accounts/"), "/sessions")
		if id == "" || strings.Contains(id, "/") {
			problem(w, 404, "Account not found")
			return
		}
		a.revokeSessions(w, r, sess, id)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/accounts")
	if id != "" {
		if !strings.HasPrefix(id, "/") || strings.Count(id, "/") != 1 {
			problem(w, 404, "Account not found")
			return
		}
		id = strings.TrimPrefix(id, "/")
		if id == "" {
			problem(w, 404, "Account not found")
			return
		}
	}
	if r.Method == "GET" && id == "" {
		list, err := a.service.AccountsFor(sess.AccountID)
		if err != nil {
			problem(w, 500, "Accounts could not be read")
			return
		}
		jsonReply(w, 200, list)
		return
	}
	if sess.Role == "user" {
		problem(w, 403, "Administrator access required")
		return
	}
	if !((id == "" && r.Method == "POST") || (id != "" && (r.Method == "PUT" || r.Method == "DELETE"))) {
		problem(w, 405, "Method not allowed")
		return
	}
	var v struct {
		DeviceLimit *int   `json:"deviceLimit"`
		Note        string `json:"note"`
		Login       string `json:"login"`
		Role        string `json:"role"`
		ManagerID   string `json:"managerId"`
		Enabled     bool   `json:"enabled"`
		Revision    int64  `json:"revision"`
		Password    string `json:"password"`
		Confirm     bool   `json:"confirm"`
	}
	if !decode(w, r, &v) {
		return
	}
	remove := r.Method == "DELETE"
	if remove && !v.Confirm {
		problem(w, 400, "Confirm account deletion")
		return
	}
	limit := model.DefaultDeviceLimit
	if id != "" {
		old, err := a.service.Store.Account(id)
		if err != nil {
			problem(w, 404, "Account not found")
			return
		}
		limit = old.DeviceLimit
	}
	if v.DeviceLimit != nil {
		limit = *v.DeviceLimit
	}
	next := store.Account{DeviceLimit: limit, Note: v.Note, ID: id, Login: v.Login, Role: v.Role, ManagerID: v.ManagerID, Enabled: v.Enabled, Revision: v.Revision}
	if remove {
		// Deletion accepts just confirmation and the current revision.
		old, err := a.service.Store.Account(id)
		if err != nil {
			problem(w, 404, "Account not found")
			return
		}
		next = old
		next.Revision = v.Revision
	}
	result, err := a.service.WriteAccount(r.Context(), sess.AccountID, next, v.Password, remove)
	if errors.Is(err, service.ErrAccess) {
		problem(w, 404, "Account not found or access denied")
		return
	}
	if errors.Is(err, store.ErrSettingsConflict) {
		problem(w, 409, "Account changed; reload before saving")
		return
	}
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	// Account writes hold configMu exclusively, so login/requests cannot race
	// revocation, transfers or changes in inherited account blocking.
	all, err := a.service.Store.Accounts()
	if err != nil {
		a.mu.Lock()
		a.sessions = map[string]session{}
		clear(a.challenges)
		clear(a.enrollments)
		a.mu.Unlock()
		problem(w, 500, "Account saved; sign in again")
		return
	}
	revoke := map[string]bool{result.ID: true}
	for _, acc := range all {
		if acc.ManagerID == result.ID {
			revoke[acc.ID] = true
		}
	}
	a.mu.Lock()
	for id := range revoke {
		a.revokeAccount(id, "")
	}
	a.mu.Unlock()
	status := 200
	if id == "" {
		status = 201
	}
	jsonReply(w, status, result)
}

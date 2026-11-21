package httpapi

import (
	"awg-panel/internal/auth"
	"net/http"
)

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	if !a.allowed(a.requestIP(r).String()) {
		w.Header().Set("Retry-After", "30")
		problem(w, 429, "Too many password attempts; try again later")
		return
	}
	var v struct {
		Code    string `json:"code"`
		Current string `json:"currentPassword"`
		New     string `json:"newPassword"`
		Confirm string `json:"confirmPassword"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.Current) > 256 || len(v.New) < 12 || len(v.New) > 256 {
		problem(w, 400, "Password must contain 12 to 256 bytes")
		return
	}
	if v.New != v.Confirm {
		problem(w, 400, "New passwords do not match")
		return
	}
	if v.Current == v.New {
		problem(w, 400, "Choose a different password")
		return
	}
	// Login and password changes share a gate: an old-password login cannot create
	// a fresh session after revocation. Recheck this request's session after entry.
	select {
	case a.loginGate <- struct{}{}:
		defer func() { <-a.loginGate }()
	default:
		problem(w, 429, "Authentication is busy; try again shortly")
		return
	}
	sess, ok := a.current(r)
	if !ok {
		problem(w, 401, "Authentication required")
		return
	}
	account, err := a.service.Store.Account(sess.AccountID)
	if err != nil {
		problem(w, 500, "Credentials could not be read")
		return
	}
	if !auth.VerifyPassword(account.PasswordHash, v.Current) {
		problem(w, 400, "Current password is incorrect")
		return
	}
	if err = a.service.Store.ReplacePassword(account.ID, account.PasswordHash, v.New, v.Code); err != nil {
		mfaProblem(w, err, false)
		return
	}
	a.mu.Lock()
	a.revokeAccount(account.ID, "")
	a.mu.Unlock()
	a.cookie(w, r, "", -1)
	jsonReply(w, 200, map[string]bool{"ok": true})
}

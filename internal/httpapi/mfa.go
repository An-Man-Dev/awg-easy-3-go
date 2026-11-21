package httpapi

import (
	"awg-panel/internal/auth"
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"encoding/base64"
	"errors"
	qrcode "github.com/skip2/go-qrcode"
	"net/http"
	"strings"
	"time"
)

type loginChallenge struct {
	AccountID string
	Revision  int64
	Expires   time.Time
	IP        string
	Secure    bool
	Attempts  int
}
type enrollment struct {
	AccountID, Secret string
	Revision          int64
	Expires           time.Time
}

func (a *API) challengeCookie(w http.ResponseWriter, r *http.Request, token string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "awg_challenge", Value: token, Path: "/api/login", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.secure(r), MaxAge: age})
}
func (a *API) pruneMFA() {
	now := time.Now()
	for token, c := range a.challenges {
		if !now.Before(c.Expires) {
			delete(a.challenges, token)
		}
	}
	for token, c := range a.enrollments {
		if !now.Before(c.Expires) {
			delete(a.enrollments, token)
		}
	}
}

// Caller holds mu. Keep only the session that just supplied fresh credentials.
func (a *API) revokeAccount(id, keep string) {
	for token, t := range a.transfers {
		if t.AccountID == id {
			delete(a.transfers, token)
		}
	}
	for token, s := range a.sessions {
		if s.AccountID == id && token != keep {
			delete(a.sessions, token)
		}
	}
	for token, c := range a.challenges {
		if c.AccountID == id {
			delete(a.challenges, token)
		}
	}
	for token, c := range a.enrollments {
		if c.AccountID == id {
			delete(a.enrollments, token)
		}
	}
}
func (a *API) beginChallenge(w http.ResponseWriter, r *http.Request, account store.Account) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneMFA()
	if old, err := r.Cookie("awg_challenge"); err == nil {
		delete(a.challenges, old.Value)
	}
	count := 0
	for _, c := range a.challenges {
		if c.AccountID == account.ID {
			count++
		}
	}
	if len(a.challenges) >= 128 || count >= 4 {
		problem(w, 429, "Too many pending sign-ins; try again in 5 minutes")
		return
	}
	if old, err := r.Cookie("awg_session"); err == nil {
		delete(a.sessions, old.Value)
		delete(a.enrollments, old.Value)
	}
	token := model.Random(32)
	a.challenges[token] = loginChallenge{AccountID: account.ID, Revision: account.Revision, Expires: time.Now().Add(5 * time.Minute), IP: a.requestIP(r).String(), Secure: a.secure(r)}
	a.cookie(w, r, "", -1)
	a.challengeCookie(w, r, token, 300)
	jsonReply(w, 200, map[string]any{"mfaRequired": true, "expiresIn": 300})
}
func mfaProblem(w http.ResponseWriter, err error, login bool) {
	if errors.Is(err, store.ErrMFARate) {
		w.Header().Set("Retry-After", "300")
		problem(w, 429, err.Error())
		return
	}
	if errors.Is(err, store.ErrMFAInvalid) {
		status := 400
		if login {
			status = 401
		}
		problem(w, status, err.Error())
		return
	}
	if errors.Is(err, store.ErrCredentialsChanged) {
		problem(w, 409, "Account security changed; sign in again")
		return
	}
	if errors.Is(err, store.ErrMFADisabled) {
		problem(w, 409, "Two-factor authentication is not enabled; sign in again")
		return
	}
	problem(w, 500, "Two-factor operation could not be completed; reload before retrying")
}
func (a *API) verifyLogin(w http.ResponseWriter, r *http.Request) {
	if !a.allowed(a.requestIP(r).String()) {
		w.Header().Set("Retry-After", "30")
		problem(w, 429, "Too many login attempts; try again later")
		return
	}
	var v struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &v) {
		return
	}
	cookie, err := r.Cookie("awg_challenge")
	if err != nil {
		problem(w, 401, "Sign-in expired; start again with your password")
		return
	}
	a.mu.Lock()
	a.pruneMFA()
	c, ok := a.challenges[cookie.Value]
	if !ok || c.IP != a.requestIP(r).String() || (c.Secure && !a.secure(r)) || c.Attempts >= 5 {
		a.mu.Unlock()
		problem(w, 401, "Sign-in expired; start again with your password")
		return
	}
	c.Attempts++
	a.challenges[cookie.Value] = c
	a.mu.Unlock()
	// SQLite commits the replay counter or consumed recovery code before a session
	// can be created. Account revisions invalidate pre-password-reset challenges.
	if err = a.service.Store.VerifyMFA(c.AccountID, c.Revision, strings.TrimSpace(v.Code), time.Now()); err != nil {
		if c.Attempts >= 5 || errors.Is(err, store.ErrCredentialsChanged) || errors.Is(err, store.ErrMFADisabled) {
			a.mu.Lock()
			delete(a.challenges, cookie.Value)
			a.mu.Unlock()
			a.challengeCookie(w, r, "", -1)
		}
		mfaProblem(w, err, true)
		return
	}
	a.mu.Lock()
	_, ok = a.challenges[cookie.Value]
	delete(a.challenges, cookie.Value)
	a.mu.Unlock()
	if !ok {
		problem(w, 401, "Sign-in already completed; start again")
		return
	}
	a.challengeCookie(w, r, "", -1)
	a.newSession(w, r, c.AccountID)
}
func (a *API) mfa(w http.ResponseWriter, r *http.Request, sess session) {
	if r.Method == "GET" && r.URL.Path == "/api/account/totp" {
		status, err := a.service.Store.MFAStatus(sess.AccountID)
		if err != nil {
			mfaProblem(w, err, false)
			return
		}
		jsonReply(w, 200, status)
		return
	}
	if r.Method != "POST" && r.Method != "DELETE" {
		problem(w, 405, "Method not allowed")
		return
	}
	cookie, _ := r.Cookie("awg_session")
	if r.Method == "DELETE" && r.URL.Path == "/api/account/totp/setup" {
		a.mu.Lock()
		delete(a.enrollments, cookie.Value)
		a.mu.Unlock()
		jsonReply(w, 200, map[string]bool{"ok": true})
		return
	}
	var v struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		Confirm  bool   `json:"confirm"`
	}
	if !decode(w, r, &v) {
		return
	}
	if !a.allowed(a.requestIP(r).String()) {
		w.Header().Set("Retry-After", "30")
		problem(w, 429, "Too many security attempts; try again later")
		return
	}
	account, err := a.service.Store.Account(sess.AccountID)
	if err != nil {
		mfaProblem(w, err, false)
		return
	}
	if r.Method == "POST" && r.URL.Path == "/api/account/totp/confirm" {
		a.mu.Lock()
		a.pruneMFA()
		pending, ok := a.enrollments[cookie.Value]
		a.mu.Unlock()
		if !ok || pending.AccountID != account.ID || pending.Revision != account.Revision {
			problem(w, 409, "Setup expired or account changed; start setup again")
			return
		}
		codes, e := a.service.Store.EnableMFA(account.ID, pending.Revision, pending.Secret, strings.TrimSpace(v.Code), time.Now())
		if e != nil {
			mfaProblem(w, e, false)
			return
		}
		a.mu.Lock()
		a.revokeAccount(account.ID, cookie.Value)
		a.mu.Unlock()
		jsonReply(w, 200, map[string]any{"enabled": true, "recoveryCodes": codes})
		return
	}
	if len(v.Password) > 256 || !auth.VerifyPassword(account.PasswordHash, v.Password) {
		problem(w, 400, "Current password is incorrect")
		return
	}
	if r.Method == "POST" && r.URL.Path == "/api/account/totp/setup" {
		status, e := a.service.Store.MFAStatus(account.ID)
		if e != nil {
			mfaProblem(w, e, false)
			return
		}
		if status.Enabled {
			problem(w, 409, "TOTP is already enabled")
			return
		}
		secret, e := auth.NewTOTPSecret()
		if e != nil {
			mfaProblem(w, e, false)
			return
		}
		uri := auth.TOTPURI(secret, account.Login)
		png, e := qrcode.Encode(uri, qrcode.Medium, 384)
		if e != nil {
			mfaProblem(w, e, false)
			return
		}
		a.mu.Lock()
		a.pruneMFA()
		a.enrollments[cookie.Value] = enrollment{AccountID: account.ID, Revision: account.Revision, Secret: secret, Expires: time.Now().Add(5 * time.Minute)}
		a.mu.Unlock()
		jsonReply(w, 200, map[string]any{"secret": secret, "uri": uri, "qr": base64.StdEncoding.EncodeToString(png), "expiresIn": 300})
		return
	}
	disable := r.Method == "DELETE" && r.URL.Path == "/api/account/totp"
	if !disable && !(r.Method == "POST" && r.URL.Path == "/api/account/totp/recovery-codes") {
		problem(w, 404, "Endpoint not found")
		return
	}
	if !v.Confirm {
		problem(w, 400, "Confirm this security change")
		return
	}
	codes, err := a.service.Store.ManageMFA(account.ID, account.PasswordHash, strings.TrimSpace(v.Code), disable, time.Now())
	if err != nil {
		mfaProblem(w, err, false)
		return
	}
	a.mu.Lock()
	a.revokeAccount(account.ID, cookie.Value)
	a.mu.Unlock()
	jsonReply(w, 200, map[string]any{"enabled": !disable, "recoveryCodes": codes})
}
func (a *API) revokeSessions(w http.ResponseWriter, r *http.Request, sess session, id string) {
	target, err := a.service.Store.Account(id)
	actor, e := a.service.Store.Account(sess.AccountID)
	if err != nil || e != nil || !actor.CanManage(target) {
		problem(w, 404, "Account not found")
		return
	}
	if err = a.service.Store.RecordSessionRevocation(actor.ID, id); err != nil {
		problem(w, 500, "Sessions could not be revoked")
		return
	}
	a.mu.Lock()
	a.revokeAccount(id, "")
	a.mu.Unlock()
	if id == actor.ID {
		a.cookie(w, r, "", -1)
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}

func (a *API) adminResetMFA(w http.ResponseWriter, r *http.Request, sess session, id string) {
	actor, err := a.service.Store.Account(sess.AccountID)
	target, e := a.service.Store.Account(id)
	if err != nil || e != nil || actor.Role == "user" || !actor.CanManage(target) {
		problem(w, 404, "Account not found")
		return
	}
	var v struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		Confirm  bool   `json:"confirm"`
	}
	if !decode(w, r, &v) {
		return
	}
	if !v.Confirm {
		problem(w, 400, "Confirm that this account will lose its second factor and saved recovery codes")
		return
	}
	if !a.allowed(a.requestIP(r).String()) {
		w.Header().Set("Retry-After", "30")
		problem(w, 429, "Too many security attempts; try again later")
		return
	}
	if len(v.Password) > 256 || !auth.VerifyPassword(actor.PasswordHash, v.Password) {
		problem(w, 400, "Your current password is incorrect")
		return
	}
	if err = a.service.Store.AdminResetMFA(actor.ID, id, actor.PasswordHash, strings.TrimSpace(v.Code), time.Now()); err != nil {
		mfaProblem(w, err, false)
		return
	}
	a.mu.Lock()
	a.revokeAccount(id, "")
	a.mu.Unlock()
	if id == actor.ID {
		a.cookie(w, r, "", -1)
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}

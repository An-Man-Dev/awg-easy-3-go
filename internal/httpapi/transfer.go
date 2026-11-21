package httpapi

import (
	"awg-panel/internal/auth"
	"awg-panel/internal/model"
	"awg-panel/internal/portable"
	"crypto/sha256"
	"net/http"
	"time"
)

// Tickets contain no decrypted data or encryption credential. They bind a short
// lived reauthentication to the exact archive, destination and browser session.
type importTicket struct {
	Token, AccountID, Fingerprint string
	Revision                      int64
	Hash                          [32]byte
	Expires                       time.Time
}
type transferRequest struct {
	Password string `json:"currentPassword"`
	Code     string `json:"code"`
	Secret   string `json:"secret"`
	Mode     string `json:"mode"`
	Include  bool   `json:"includeClientKeys"`
	Archive  []byte `json:"archive"`
	Ticket   string `json:"ticket"`
	Confirm  bool   `json:"confirm"`
}

func (a *API) transfer(w http.ResponseWriter, r *http.Request, sess session) {
	if sess.Role != "superadmin" {
		problem(w, 403, "Superadministrator access required")
		return
	}
	if r.URL.Path == "/api/transfer" && r.Method == "GET" {
		requirements, available := a.service.TransferInfo()
		jsonReply(w, 200, map[string]any{"requirements": requirements, "importAvailable": available})
		return
	}
	if r.Method != "POST" {
		problem(w, 405, "Method not allowed")
		return
	}
	path := r.URL.Path
	if path != "/api/transfer/export" && path != "/api/transfer/preview" && path != "/api/transfer/import" {
		problem(w, 404, "Not found")
		return
	}
	if path != "/api/transfer/export" && (model.IsVPN(peerIP(r)) || model.IsVPN(a.requestIP(r))) {
		problem(w, 400, "Open the external panel address to import: the initial VPN device will be replaced")
		return
	}
	if !a.allowed(a.requestIP(r).String()) {
		w.Header().Set("Retry-After", "30")
		problem(w, 429, "Too many attempts; try again later")
		return
	}
	var v transferRequest
	limit := int64(8192)
	if path != "/api/transfer/export" {
		limit = 12 << 20
	}
	if !decodeLimit(w, r, &v, limit) {
		return
	}
	defer clear(v.Archive)
	if len(v.Archive) > portable.MaxSize || len(v.Secret) > 256 || len(v.Password) > 256 || len(v.Code) > 128 {
		problem(w, 400, "Invalid transfer request")
		return
	}
	owner, err := a.service.Store.Account(sess.AccountID)
	if err != nil {
		problem(w, 500, "Account could not be read")
		return
	}
	cookie, err := r.Cookie("awg_session")
	if err != nil {
		problem(w, 401, "Authentication required")
		return
	}
	if path != "/api/transfer/import" {
		if !auth.VerifyPassword(owner.PasswordHash, v.Password) {
			problem(w, 400, "Current account password is incorrect")
			return
		}
		status, err := a.service.Store.MFAStatus(owner.ID)
		if err != nil {
			problem(w, 500, "Second factor status could not be read")
			return
		}
		if status.Enabled {
			if err = a.service.Store.VerifyMFA(owner.ID, owner.Revision, v.Code, time.Now()); err != nil {
				mfaProblem(w, err, false)
				return
			}
		}
	}
	if path == "/api/transfer/export" {
		data, err := a.service.ExportArchive(v.Include, v.Mode, v.Secret)
		if err != nil {
			problem(w, 400, err.Error())
			return
		}
		defer clear(data)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="awg-configuration.awgbackup"`)
		w.Write(data)
		return
	}
	hash := sha256.Sum256(v.Archive)
	var ticket importTicket
	if path == "/api/transfer/import" {
		a.mu.Lock()
		ticket = a.transfers[cookie.Value]
		delete(a.transfers, cookie.Value)
		a.mu.Unlock()
		if !v.Confirm || ticket.Token == "" || ticket.Token != v.Ticket || ticket.AccountID != owner.ID || ticket.Revision != owner.Revision || ticket.Hash != hash || !time.Now().Before(ticket.Expires) {
			problem(w, 409, "Preview expired or changed; preview the archive again")
			return
		}
	}
	snapshot, err := portable.Decrypt(v.Archive, v.Secret)
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	if path == "/api/transfer/preview" {
		fingerprint, err := a.service.CheckImport(snapshot)
		if err != nil {
			problem(w, 409, err.Error())
			return
		}
		ticket = importTicket{Token: model.Random(32), AccountID: owner.ID, Revision: owner.Revision, Hash: hash, Fingerprint: fingerprint, Expires: time.Now().Add(5 * time.Minute)}
		a.mu.Lock()
		for key, t := range a.transfers {
			if _, ok := a.sessions[key]; !ok || !time.Now().Before(t.Expires) {
				delete(a.transfers, key)
			}
		}
		a.transfers[cookie.Value] = ticket
		a.mu.Unlock()
		jsonReply(w, 200, map[string]any{"summary": snapshot.Summary(), "ticket": ticket.Token, "expiresIn": 300})
		return
	}
	if err = a.service.ImportArchive(r.Context(), snapshot, ticket.Fingerprint); err != nil {
		problem(w, 409, err.Error())
		return
	}
	a.config.Host = snapshot.State.Addresses.VPNHost
	a.config.PublicOrigin = snapshot.State.Addresses.PanelOrigin
	a.setOrigins()
	a.mu.Lock()
	clear(a.sessions)
	clear(a.challenges)
	clear(a.enrollments)
	clear(a.transfers)
	a.mu.Unlock()
	a.cookie(w, r, "", -1)
	jsonReply(w, 200, map[string]any{"ok": true, "panelOrigin": a.config.PublicOrigin, "login": snapshot.Summary().SuperadminLogin})
}

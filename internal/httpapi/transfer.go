package httpapi

import (
	"awg-panel/internal/auth"
	"awg-panel/internal/model"
	"awg-panel/internal/portable"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Tickets contain no decrypted data or encryption credential. They bind a short
// lived reauthentication to the exact archive, destination and browser session.
type importTicket struct {
	Token, AccountID, Fingerprint string
	Revision                      int64
	Hash                          [32]byte
	SelectionHash                 [32]byte
	Planned                       bool
	Expires                       time.Time
}
type transferRequest struct {
	Password  string              `json:"currentPassword"`
	Code      string              `json:"code"`
	Secret    string              `json:"secret"`
	Mode      string              `json:"mode"`
	Include   bool                `json:"includeClientKeys"`
	Archive   []byte              `json:"archive"`
	Ticket    string              `json:"ticket"`
	Confirm   bool                `json:"confirm"`
	Selection *portable.Selection `json:"selection,omitempty"`
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
	if path != "/api/transfer/export" && path != "/api/transfer/preview" && path != "/api/transfer/import" && path != "/api/transfer/inspect" {
		problem(w, 404, "Not found")
		return
	}
	if path != "/api/transfer/export" && (model.IsVPN(peerIP(r)) || model.IsVPN(a.requestIP(r))) {
		problem(w, 400, "Open the external panel address to import: VPN devices and server identity may be replaced")
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
	hash := sha256.Sum256(v.Archive)
	selectionBytes, _ := json.Marshal(v.Selection)
	selectionHash := sha256.Sum256(selectionBytes)
	var proof importTicket
	if path == "/api/transfer/preview" && v.Ticket != "" {
		a.mu.Lock()
		proof = a.transfers[cookie.Value]
		a.mu.Unlock()
		if proof.Token != v.Ticket || proof.AccountID != owner.ID || proof.Revision != owner.Revision || proof.Hash != hash || !time.Now().Before(proof.Expires) {
			problem(w, 409, "Archive inspection expired; inspect again")
			return
		}
	}
	if path != "/api/transfer/import" && proof.Token == "" {
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
	var ticket importTicket
	if path == "/api/transfer/import" {
		a.mu.Lock()
		ticket = a.transfers[cookie.Value]
		delete(a.transfers, cookie.Value)
		a.mu.Unlock()
		if !ticket.Planned || ticket.SelectionHash != selectionHash || !v.Confirm || ticket.Token == "" || ticket.Token != v.Ticket || ticket.AccountID != owner.ID || ticket.Revision != owner.Revision || ticket.Hash != hash || !time.Now().Before(ticket.Expires) {
			problem(w, 409, "Preview expired or changed; preview the archive again")
			return
		}
	}
	snapshot, err := portable.Decrypt(v.Archive, v.Secret)
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	if path == "/api/transfer/preview" || path == "/api/transfer/inspect" {
		current, fingerprint, err := a.service.InspectImport()
		result := snapshot
		plan := portable.MergePlan{Changes: []string{}, Warnings: []string{}}
		if err == nil && path == "/api/transfer/preview" {
			if v.Selection != nil {
				result, plan, err = portable.Merge(current, snapshot, *v.Selection)
			} else if current.Requirements != snapshot.Requirements {
				problem(w, 409, "Protocol, ports, subnets and IPv6 mode must match for full replacement")
				return
			}
		}
		if err != nil {
			problem(w, 409, err.Error())
			return
		}
		ticket = importTicket{Token: model.Random(32), AccountID: owner.ID, Revision: owner.Revision, Hash: hash, Fingerprint: fingerprint, SelectionHash: selectionHash, Planned: path == "/api/transfer/preview", Expires: time.Now().Add(5 * time.Minute)}
		if proof.Token != "" {
			ticket.Expires = proof.Expires
		}
		a.mu.Lock()
		for key, t := range a.transfers {
			if _, ok := a.sessions[key]; !ok || !time.Now().Before(t.Expires) {
				delete(a.transfers, key)
			}
		}
		a.transfers[cookie.Value] = ticket
		a.mu.Unlock()
		jsonReply(w, 200, map[string]any{"summary": result.Summary(), "plan": plan, "selective": v.Selection != nil, "resultInventory": importInventory(result), "current": current.Summary(), "currentInventory": importInventory(current), "incomingInventory": importInventory(snapshot), "ticket": ticket.Token, "expiresIn": max(1, int(time.Until(ticket.Expires).Seconds()))})
		return
	}
	snapshot, err = a.service.ImportSelection(r.Context(), snapshot, ticket.Fingerprint, v.Selection)
	if err != nil {
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

// Only names and identifiers reach the preview; never serialize the snapshot.
func importInventory(s portable.Snapshot) map[string]any {
	accounts := make([]map[string]string, 0, len(s.Accounts))
	devices := make([]map[string]string, 0, len(s.State.Peers))
	for _, a := range s.Accounts {
		accounts = append(accounts, map[string]string{"id": a.ID, "login": a.Login, "role": a.Role, "managerId": a.ManagerID, "deviceLimit": fmt.Sprint(a.DeviceLimit), "enabled": fmt.Sprint(a.Enabled)})
	}
	for _, p := range s.State.Peers {
		devices = append(devices, map[string]string{"id": p.ID, "name": p.Name, "ownerId": p.OwnerID, "slot": fmt.Sprint(p.Slot), "group": p.Group, "enabled": fmt.Sprint(p.Enabled)})
	}
	return map[string]any{"accounts": accounts, "devices": devices}
}

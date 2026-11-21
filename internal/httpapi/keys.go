package httpapi

import (
	"awg-panel/internal/artifact"
	"awg-panel/internal/model"
	"awg-panel/internal/service"
	"awg-panel/internal/store"
	"encoding/base64"
	"errors"
	qrcode "github.com/skip2/go-qrcode"
	"net/http"
)

func (a *API) keyPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		jsonReply(w, 200, a.service.KeyPolicy())
		return
	}
	if r.Method != "PUT" {
		problem(w, 405, "Method not allowed")
		return
	}
	var next model.KeyPolicy
	if !decode(w, r, &next) {
		return
	}
	if err := next.Validate(); err != nil {
		problem(w, 400, err.Error())
		return
	}
	result, err := a.service.UpdateKeyPolicy(next)
	if errors.Is(err, store.ErrSettingsConflict) {
		problem(w, 409, err.Error())
		return
	}
	if err != nil {
		problem(w, 500, "Key policy could not be saved")
		return
	}
	jsonReply(w, 200, result)
}
func (a *API) purgeKeys(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Revision int64  `json:"revision"`
		Version  string `json:"deleteVersion"`
		Confirm  bool   `json:"confirm"`
	}
	if !decode(w, r, &v) {
		return
	}
	if !v.Confirm || v.Version == "" {
		problem(w, 400, "Explicit confirmation of stored key deletion is required")
		return
	}
	count, err := a.service.PurgeKeys(v.Revision, v.Version)
	if errors.Is(err, store.ErrSettingsConflict) {
		problem(w, 409, "Stored keys or policy changed; reload the deletion preview")
		return
	}
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	jsonReply(w, 200, map[string]int64{"deleted": count})
}
func issuanceReply(w http.ResponseWriter, status int, issued service.Issuance) {
	// Generate QR from the exact response snapshot, without a key-bearing GET URL
	// or server-side cache. If QR fails, configuration and link are still usable.
	frames := []string{}
	chunks, err := artifact.QRChunks(issued.Link)
	if err == nil {
		for _, chunk := range chunks {
			png, e := qrcode.Encode(chunk, qrcode.Low, 768)
			if e != nil {
				frames = nil
				break
			}
			frames = append(frames, base64.StdEncoding.EncodeToString(png))
		}
	}
	jsonReply(w, status, struct {
		service.Issuance
		QRFrames []string `json:"qrFrames"`
	}{issued, frames})
}
func (a *API) reissue(w http.ResponseWriter, r *http.Request, id, actor string) {
	var v struct {
		Version string `json:"keyVersion"`
		Confirm bool   `json:"confirm"`
	}
	if !decode(w, r, &v) {
		return
	}
	if !v.Confirm || v.Version == "" {
		problem(w, 400, "Confirm that the previous profile will stop working")
		return
	}
	for _, p := range a.service.List() {
		if p.ID != id {
			continue
		}
		for _, ip := range []string{peerIP(r).String(), a.requestIP(r).String()} {
			if ip == p.Address4 || ip == p.Address6 {
				problem(w, 409, "Reissue from another home device or the external panel; this connection would be interrupted before delivery")
				return
			}
		}
	}
	issued, err := a.service.IssueFor(r.Context(), actor, "", id, "", "", v.Version)
	if errors.Is(err, service.ErrKeyConflict) {
		problem(w, 409, err.Error())
		return
	}
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	issuanceReply(w, 200, issued)
}

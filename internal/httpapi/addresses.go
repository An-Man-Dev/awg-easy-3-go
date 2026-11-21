package httpapi

import (
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"errors"
	"net/http"
)

// ServeHTTP holds configMu exclusively for this endpoint, making configuration,
// allowed origins and session revocation visible together to other requests.
func (a *API) changeAddresses(w http.ResponseWriter, r *http.Request) {
	var next model.Addresses
	if !decode(w, r, &next) {
		return
	}
	if err := next.Validate(); err != nil {
		problem(w, 400, err.Error())
		return
	}
	result, err := a.service.UpdateAddresses(r.Context(), next)
	if errors.Is(err, store.ErrSettingsConflict) {
		problem(w, 409, err.Error())
		return
	}
	if err != nil {
		problem(w, 500, err.Error())
		return
	}
	a.config.Host = result.VPNHost
	a.config.PublicOrigin = result.PanelOrigin
	a.setOrigins()
	a.mu.Lock()
	clear(a.transfers)
	clear(a.sessions)
	clear(a.challenges)
	clear(a.enrollments)
	a.mu.Unlock()
	a.cookie(w, r, "", -1)
	jsonReply(w, 200, result)
}

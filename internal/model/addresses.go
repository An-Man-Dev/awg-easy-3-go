package model

import (
	"awg-panel/internal/config"
	"fmt"
)

type Addresses struct {
	Revision    int64  `json:"revision"`
	VPNHost     string `json:"vpnHost"`
	PanelOrigin string `json:"panelOrigin"`
}

func (a Addresses) Validate() error {
	if a.Revision < 1 {
		return fmt.Errorf("invalid address revision")
	}
	if !config.ValidHost(a.VPNHost) {
		return fmt.Errorf("VPN host must be a domain or IP without a scheme or port")
	}
	if _, err := config.PublicOrigin(a.PanelOrigin); err != nil {
		return err
	}
	return nil
}

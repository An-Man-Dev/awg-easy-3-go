package store

import (
	"awg-panel/internal/model"
	"context"
	"database/sql"
	"strings"
	"time"
)

func readAddresses(ctx context.Context, tx *sql.Tx) (*model.Addresses, error) {
	var a model.Addresses
	err := tx.QueryRowContext(ctx, "SELECT revision,vpn_host,panel_origin FROM server_addresses WHERE id=1").Scan(&a.Revision, &a.VPNHost, &a.PanelOrigin)
	if err != nil {
		return nil, err
	}
	return &a, a.Validate()
}
func (s *Store) SaveAddresses(next model.Addresses, expected int64) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if next.Revision != expected+1 {
		return ErrSettingsConflict
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	before, err := readAddresses(ctx, tx)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "UPDATE server_addresses SET revision=?,vpn_host=?,panel_origin=? WHERE id=1 AND revision=?", next.Revision, next.VPNHost, next.PanelOrigin, expected)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrSettingsConflict
	}
	fields := []string{}
	if before.VPNHost != next.VPNHost {
		fields = append(fields, "vpnHost")
	}
	if before.PanelOrigin != next.PanelOrigin {
		fields = append(fields, "panelOrigin")
	}
	if len(fields) > 0 {
		if err = writeAudit(ctx, tx, AuditRecord{Actor: model.BootstrapAccountID, Action: "addresses.update", Target: strings.Join(fields, ",")}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

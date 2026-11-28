package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"awg-panel/internal/model"
)

var ErrSettingsConflict = errors.New("settings changed in another session; reload before saving")

func clientJSON(c model.ClientSettings) (string, string) {
	dns, _ := json.Marshal(c.DNS)
	routes, _ := json.Marshal(c.AllowedIPs)
	return string(dns), string(routes)
}
func decodeClient(dns, routes string, mtu, keepalive int) (model.ClientSettings, error) {
	c := model.ClientSettings{MTU: mtu, PersistentKeepalive: keepalive}
	if err := json.Unmarshal([]byte(dns), &c.DNS); err != nil {
		return c, err
	}
	if err := json.Unmarshal([]byte(routes), &c.AllowedIPs); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func readSettings(ctx context.Context, tx *sql.Tx) (*model.Settings, error) {
	var s model.Settings
	var dns, routes string
	err := tx.QueryRowContext(ctx, "SELECT revision,server_name,dns,mtu,keepalive,allowed_ips FROM app_settings WHERE id=1").Scan(&s.Revision, &s.ServerName, &dns, &s.Client.MTU, &s.Client.PersistentKeepalive, &routes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.Client, err = decodeClient(dns, routes, s.Client.MTU, s.Client.PersistentKeepalive)
	if err != nil {
		return nil, err
	}
	return &s, s.Validate()
}

// SaveSettings changes the single global export policy, without touching devices or keys.
func (s *Store) SaveSettings(next model.Settings, expected int64) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if next.Revision != expected+1 {
		return ErrSettingsConflict
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	before, err := readSettings(ctx, tx)
	if err != nil {
		return err
	}
	if before == nil || before.Revision != expected {
		return ErrSettingsConflict
	}
	dns, routes := clientJSON(next.Client)
	result, err := tx.ExecContext(ctx, `UPDATE app_settings SET revision=?,server_name=?,dns=?,mtu=?,keepalive=?,allowed_ips=? WHERE id=1 AND revision=?`, next.Revision, next.ServerName, dns, next.Client.MTU, next.Client.PersistentKeepalive, routes, expected)
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
	if before.ServerName != next.ServerName {
		fields = append(fields, "serverName")
	}
	if !reflect.DeepEqual(before.Client.DNS, next.Client.DNS) {
		fields = append(fields, "dns")
	}
	if before.Client.MTU != next.Client.MTU {
		fields = append(fields, "mtu")
	}
	if before.Client.PersistentKeepalive != next.Client.PersistentKeepalive {
		fields = append(fields, "keepalive")
	}
	if !reflect.DeepEqual(before.Client.AllowedIPs, next.Client.AllowedIPs) {
		fields = append(fields, "routes")
	}
	if len(fields) > 0 {
		// Global settings are writable only by the single protected superadministrator.
		if err = writeAudit(ctx, tx, AuditRecord{Actor: model.BootstrapAccountID, Action: "settings.update", Target: strings.Join(fields, ",")}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	return tx.Commit()
}

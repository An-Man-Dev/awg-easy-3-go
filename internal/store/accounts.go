package store

import (
	"context"
	"fmt"
	"time"

	"awg-panel/internal/auth"
	"awg-panel/internal/model"
)

type Account struct {
	ID           string `json:"id"`
	Login        string `json:"login"`
	Role         string `json:"role"`
	Enabled      bool   `json:"enabled"`
	Active       bool   `json:"active"`
	ManagerID    string `json:"managerId"`
	Revision     int64  `json:"revision"`
	CreatedAt    string `json:"createdAt"`
	TOTPEnabled  bool   `json:"totpEnabled"`
	PasswordHash string `json:"-"`
}

func (s *Store) Initialized() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var initialized bool
	err := s.db.QueryRowContext(ctx, "SELECT initialized FROM metadata WHERE id=1").Scan(&initialized)
	return initialized, err
}

// Initialize creates the account and VPN state together, only once. A changed
// environment password never overwrites credentials in an initialized database.
func (s *Store) Initialize(password string, ipv6 bool, addresses model.Addresses) error {
	initialized, err := s.Initialized()
	if err != nil || initialized {
		return err
	}
	if err = addresses.Validate(); err != nil {
		return err
	}
	// Derive credentials before taking a write transaction. CPU cost (especially
	// under race instrumentation or on a small server) is not a database timeout.
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	state, err := model.NewState()
	if err != nil {
		return err
	}
	addresses.Revision = 1
	state.Addresses = &addresses
	defaults := model.DefaultSettings(ipv6)
	state.Settings = &defaults
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Another initializer on this Store may have completed while hashing.
	if err = tx.QueryRowContext(ctx, "SELECT initialized FROM metadata WHERE id=1").Scan(&initialized); err != nil {
		return err
	}
	if initialized {
		return nil
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO accounts(id,login,password_hash,role,enabled,created_at)
 VALUES(?,?,?,'superadmin',1,?)`, model.BootstrapAccountID, "admin", hash, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO server_addresses(id,revision,vpn_host,panel_origin) VALUES(1,1,?,?)`, addresses.VPNHost, addresses.PanelOrigin); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO key_policy(id,revision,retain) VALUES(1,1,1)"); err != nil {
		return err
	}
	dns, routes := clientJSON(defaults.Client)
	if _, err = tx.ExecContext(ctx, `INSERT INTO app_settings(id,revision,server_name,dns,mtu,keepalive,allowed_ips) VALUES(1,1,?,?,?,?,?)`, defaults.ServerName, dns, defaults.Client.MTU, defaults.Client.PersistentKeepalive, routes); err != nil {
		return err
	}
	if err = saveState(ctx, tx, state); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET initialized=1 WHERE id=1"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Account(id string) (Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var a Account
	err := s.db.QueryRowContext(ctx, "SELECT "+accountColumns+",a.password_hash FROM accounts a LEFT JOIN accounts m ON m.id=a.manager_id WHERE a.id=?", id).
		Scan(&a.ID, &a.Login, &a.Role, &a.Enabled, &a.ManagerID, &a.Revision, &a.CreatedAt, &a.Active, &a.TOTPEnabled, &a.PasswordHash)
	if err == nil && !auth.ValidPasswordHash(a.PasswordHash) {
		err = fmt.Errorf("invalid stored credentials")
	}
	return a, err
}

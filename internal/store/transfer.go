package store

import (
	"awg-panel/internal/model"
	"awg-panel/internal/portable"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
)

var ErrImportCommit = errors.New("import commit status is uncertain; service must restart")

func (s *Store) ImportAvailable() bool {
	initialized, err := s.Initialized()
	return err == nil && initialized
}
func (s *Store) snapshot(ctx context.Context, tx *sql.Tx) (portable.Snapshot, error) {
	out := portable.Snapshot{Version: 1, CreatedAt: time.Now().UTC(), ClientKeysIncluded: true, Accounts: []portable.Account{}}
	var err error
	out.State, err = loadState(ctx, tx)
	if err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,login,role,enabled,COALESCE(manager_id,''),created_at,password_hash,note FROM accounts ORDER BY id")
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var a portable.Account
		if err = rows.Scan(&a.ID, &a.Login, &a.Role, &a.Enabled, &a.ManagerID, &a.CreatedAt, &a.PasswordHash, &a.Note); err != nil {
			rows.Close()
			return out, err
		}
		out.Accounts = append(out.Accounts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	for i, a := range out.Accounts {
		var sealed []byte
		var last int64
		err = tx.QueryRowContext(ctx, "SELECT secret,last_step FROM account_totp WHERE account_id=?", a.ID).Scan(&sealed, &last)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return out, err
		}
		if s.mfaBox == nil {
			return out, fmt.Errorf("TOTP encryption unavailable")
		}
		secret, e := s.mfaBox.Decrypt(a.ID, sealed)
		if e != nil {
			return out, e
		}
		m := &portable.MFA{Secret: secret, LastStep: last, RecoveryHashes: []string{}}
		rows, err = tx.QueryContext(ctx, "SELECT hash FROM recovery_codes WHERE account_id=? ORDER BY hash", a.ID)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var hash []byte
			if err = rows.Scan(&hash); err != nil {
				rows.Close()
				return out, err
			}
			m.RecoveryHashes = append(m.RecoveryHashes, base64.StdEncoding.EncodeToString(hash))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		out.Accounts[i].MFA = m
	}
	return out, nil
}
func (s *Store) Snapshot() (portable.Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return portable.Snapshot{}, err
	}
	defer tx.Rollback()
	out, err := s.snapshot(ctx, tx)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func snapshotHash(s portable.Snapshot) string {
	s.CreatedAt = time.Time{}
	b, _ := json.Marshal(s)
	defer clear(b)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (s *Store) ImportFingerprint() (string, error) {
	_, fingerprint, err := s.ImportPreview()
	return fingerprint, err
}
func (s *Store) ImportPreview() (portable.Snapshot, string, error) {
	out, err := s.Snapshot()
	if err != nil {
		return out, "", err
	}
	return out, snapshotHash(out), nil
}

// Apply runs while SQLite still owns its transaction. On application failure the
// transaction rolls back; the service restores the previous network. A process
// crash before commit leaves the previous durable state for startup to reapply.
func (s *Store) Import(ctx context.Context, in portable.Snapshot, expected string, apply func(model.State) error) (model.State, error) {
	return s.importSnapshot(ctx, in, expected, apply, false)
}
func (s *Store) ImportSelected(ctx context.Context, in portable.Snapshot, expected string, apply func(model.State) error) (model.State, error) {
	return s.importSnapshot(ctx, in, expected, apply, true)
}
func (s *Store) importSnapshot(ctx context.Context, in portable.Snapshot, expected string, apply func(model.State) error, selective bool) (model.State, error) {
	if err := in.Validate(); err != nil {
		return model.State{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.State{}, err
	}
	defer tx.Rollback()
	before, err := s.snapshot(ctx, tx)
	if err != nil {
		return model.State{}, err
	}
	if snapshotHash(before) != expected {
		return model.State{}, ErrSettingsConflict
	}
	queries := []string{"UPDATE key_policy SET retain=1 WHERE id=1"}
	if !selective {
		queries = append([]string{"DELETE FROM devices", "DELETE FROM account_totp", "DELETE FROM mfa_attempts", "DELETE FROM device_observations", "DELETE FROM audit", "DELETE FROM accounts WHERE role='user'", "DELETE FROM accounts WHERE role='admin'"}, queries...)
	}
	oldAccounts := map[string]portable.Account{}
	for _, a := range before.Accounts {
		oldAccounts[a.ID] = a
	}
	for _, query := range queries {
		if _, err = tx.ExecContext(ctx, query); err != nil {
			return model.State{}, err
		}
	}
	for _, role := range []string{"superadmin", "admin", "user"} {
		for _, a := range in.Accounts {
			if a.Role != role {
				continue
			}
			old, existed := oldAccounts[a.ID]
			if selective && existed && reflect.DeepEqual(a, old) {
				continue
			}
			if selective && existed {
				_, err = tx.ExecContext(ctx, "UPDATE accounts SET login=?,password_hash=?,enabled=?,manager_id=NULLIF(?,''),created_at=?,note=?,revision=revision+1 WHERE id=?", a.Login, a.PasswordHash, a.Enabled, a.ManagerID, a.CreatedAt, a.Note, a.ID)
			} else if role == "superadmin" {
				_, err = tx.ExecContext(ctx, "UPDATE accounts SET login=?,password_hash=?,created_at=?,note=?,revision=1 WHERE id=?", a.Login, a.PasswordHash, a.CreatedAt, a.Note, model.BootstrapAccountID)
			} else {
				_, err = tx.ExecContext(ctx, `INSERT INTO accounts(id,login,password_hash,role,enabled,manager_id,created_at,note,revision) VALUES(?,?,?,?,?,NULLIF(?,''),?,?,1)`, a.ID, a.Login, a.PasswordHash, a.Role, a.Enabled, a.ManagerID, a.CreatedAt, a.Note)
			}
			if err != nil {
				return model.State{}, err
			}
			if selective && existed && reflect.DeepEqual(a.MFA, old.MFA) {
				continue
			}
			if selective {
				if _, err = tx.ExecContext(ctx, "DELETE FROM account_totp WHERE account_id=?", a.ID); err != nil {
					return model.State{}, err
				}
				if _, err = tx.ExecContext(ctx, "DELETE FROM mfa_attempts WHERE account_id=?", a.ID); err != nil {
					return model.State{}, err
				}
			}
			if a.MFA != nil {
				if s.mfaBox == nil {
					return model.State{}, fmt.Errorf("TOTP encryption unavailable")
				}
				sealed, e := s.mfaBox.Encrypt(a.ID, a.MFA.Secret)
				if e != nil {
					return model.State{}, e
				}
				if _, err = tx.ExecContext(ctx, "INSERT INTO account_totp(account_id,secret,last_step) VALUES(?,?,?)", a.ID, sealed, a.MFA.LastStep); err != nil {
					return model.State{}, err
				}
				for _, hash := range a.MFA.RecoveryHashes {
					decoded, _ := base64.StdEncoding.Strict().DecodeString(hash)
					if _, err = tx.ExecContext(ctx, "INSERT INTO recovery_codes(account_id,hash) VALUES(?,?)", a.ID, decoded); err != nil {
						return model.State{}, err
					}
				}
			}
		}
	}
	state := in.RuntimeState()
	if err = saveState(ctx, tx, state); err != nil {
		return model.State{}, err
	}
	// Existing saved keys may accompany an off policy. Retention is restored in the
	// same transaction, before any ordinary issuance can run.
	if _, err = tx.ExecContext(ctx, "UPDATE key_policy SET revision=?,retain=? WHERE id=1", state.KeyPolicy.Revision, state.KeyPolicy.Retain); err != nil {
		return model.State{}, err
	}
	dns, routes := clientJSON(state.Settings.Client)
	if _, err = tx.ExecContext(ctx, "UPDATE app_settings SET revision=?,server_name=?,dns=?,mtu=?,keepalive=?,allowed_ips=? WHERE id=1", state.Settings.Revision, state.Settings.ServerName, dns, state.Settings.Client.MTU, state.Settings.Client.PersistentKeepalive, routes); err != nil {
		return model.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE server_addresses SET revision=?,vpn_host=?,panel_origin=? WHERE id=1", state.Addresses.Revision, state.Addresses.VPNHost, state.Addresses.PanelOrigin); err != nil {
		return model.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET import_available=0 WHERE id=1"); err != nil {
		return model.State{}, err
	}
	action := "configuration.import"
	if selective {
		action = "configuration.import.selected"
	}
	if err = writeAudit(ctx, tx, AuditRecord{Actor: model.BootstrapAccountID, Action: action, Target: "server"}); err != nil {
		return model.State{}, err
	}
	state, err = loadState(ctx, tx)
	if err != nil {
		return state, err
	}
	if err = apply(state); err != nil {
		if e := tx.Rollback(); e != nil {
			return state, ErrImportCommit
		}
		return state, err
	}
	if err = tx.Commit(); err != nil {
		return state, ErrImportCommit
	}
	return state, nil
}

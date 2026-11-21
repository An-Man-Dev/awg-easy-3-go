package store

import (
	"awg-panel/internal/auth"
	"awg-panel/internal/model"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var ErrAccountInUse = errors.New("remove devices and transfer subordinate users before deleting this account")
var ErrLoginInUse = errors.New("login is already in use")

type AuditRecord struct{ Actor, Action, Target string }
type AuditEntry struct {
	ID     int64  `json:"id"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
}

func writeAudit(ctx context.Context, tx *sql.Tx, a AuditRecord) error {
	if a.Actor == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), a.Actor, a.Action, a.Target)
	return err
}
func (s *Store) Audit() ([]AuditEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, "SELECT id,at,actor,action,target FROM audit ORDER BY id DESC LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err = rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

const accountColumns = `a.id,a.login,a.role,a.enabled,COALESCE(a.manager_id,''),a.revision,a.created_at,(a.enabled=1 AND (a.manager_id IS NULL OR m.enabled=1)),EXISTS(SELECT 1 FROM account_totp t WHERE t.account_id=a.id)`

func scanAccount(row interface{ Scan(...any) error }) (Account, error) {
	var a Account
	err := row.Scan(&a.ID, &a.Login, &a.Role, &a.Enabled, &a.ManagerID, &a.Revision, &a.CreatedAt, &a.Active, &a.TOTPEnabled)
	return a, err
}
func (s *Store) Accounts() ([]Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, "SELECT "+accountColumns+" FROM accounts a LEFT JOIN accounts m ON m.id=a.manager_id ORDER BY a.login")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := []Account{}
	for rows.Next() {
		a, e := scanAccount(rows)
		if e != nil {
			return nil, e
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}
func (a Account) CanManage(target Account) bool {
	return a.Active && (a.Role == "superadmin" || a.ID == target.ID || (a.Role == "admin" && target.Role == "user" && target.ManagerID == a.ID))
}
func ValidLogin(login string) bool {
	return regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`).MatchString(login)
}
func (s *Store) AccountByLogin(login string) (Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var id string
	if err := s.db.QueryRowContext(ctx, "SELECT id FROM accounts WHERE login=?", login).Scan(&id); err != nil {
		return Account{}, err
	}
	return s.Account(id)
}

// Called while the service serializes account/device changes. Role is immutable;
// superadministrator provisioning and removal are deliberately not exposed here.
func (s *Store) WriteAccount(actor string, next Account, password string, remove bool) (Account, error) {
	if !ValidLogin(next.Login) {
		return Account{}, fmt.Errorf("login must use 1-64 lowercase letters, digits, dots, underscores or hyphens")
	}
	if next.Role != "admin" && next.Role != "user" && next.Role != "superadmin" {
		return Account{}, fmt.Errorf("invalid role")
	}
	hash := ""
	if password != "" {
		var err error
		hash, err = auth.HashPassword(password)
		if err != nil {
			return Account{}, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	action := "account.update"
	if remove {
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM devices WHERE owner_id=?)+(SELECT count(*) FROM accounts WHERE manager_id=?)", next.ID, next.ID).Scan(&count); err != nil {
			return Account{}, err
		}
		if count != 0 {
			return Account{}, ErrAccountInUse
		}
		result, e := tx.ExecContext(ctx, "DELETE FROM accounts WHERE id=? AND revision=?", next.ID, next.Revision)
		err = e
		if err == nil {
			n, e := result.RowsAffected()
			err = e
			if n != 1 {
				return Account{}, ErrSettingsConflict
			}
		}
		action = "account.delete"
	} else if next.ID == "" {
		if hash == "" {
			return Account{}, fmt.Errorf("an initial password is required")
		}
		next.ID = model.Random(16)
		next.Revision = 1
		next.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_, err = tx.ExecContext(ctx, "INSERT INTO accounts(id,login,password_hash,role,enabled,manager_id,created_at,revision) VALUES(?,?,?,?,?,NULLIF(?,''),?,1)", next.ID, next.Login, hash, next.Role, next.Enabled, next.ManagerID, next.CreatedAt)
		action = "account.create"
	} else {
		result, e := tx.ExecContext(ctx, `UPDATE accounts SET login=?,enabled=?,manager_id=NULLIF(?,''),password_hash=CASE WHEN ?='' THEN password_hash ELSE ? END,revision=revision+1 WHERE id=? AND revision=? AND role=?`, next.Login, next.Enabled, next.ManagerID, hash, hash, next.ID, next.Revision, next.Role)
		err = e
		if err == nil {
			n, e := result.RowsAffected()
			err = e
			if n != 1 {
				return Account{}, ErrSettingsConflict
			}
		}
		next.Revision++
		if password != "" {
			action = "account.reset-password"
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: accounts.login") {
			return Account{}, ErrLoginInUse
		}
		return Account{}, err
	}
	if err = writeAudit(ctx, tx, AuditRecord{Actor: actor, Action: action, Target: next.ID}); err != nil {
		return Account{}, err
	}
	if err = tx.Commit(); err != nil {
		return Account{}, err
	}
	return next, nil
}

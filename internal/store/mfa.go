package store

import (
	"awg-panel/internal/auth"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrMFAInvalid = errors.New("invalid or already used verification code")
var ErrMFARate = errors.New("too many verification attempts; wait 5 minutes")
var ErrMFADisabled = errors.New("two-factor authentication is not enabled")

type MFAStatus struct {
	Enabled           bool `json:"enabled"`
	RecoveryRemaining int  `json:"recoveryRemaining"`
}

func (s *Store) MFAStatus(id string) (MFAStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var status MFAStatus
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_totp WHERE account_id=?),(SELECT count(*) FROM recovery_codes WHERE account_id=?)`, id, id).Scan(&status.Enabled, &status.RecoveryRemaining)
	return status, err
}
func attemptAllowed(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	var start int64
	var failures int
	err := tx.QueryRowContext(ctx, "SELECT window_start,failures FROM mfa_attempts WHERE account_id=?", id).Scan(&start, &failures)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if failures >= 5 && now.Unix() < start+300 {
		return ErrMFARate
	}
	return nil
}
func failedAttempt(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mfa_attempts(account_id,window_start,failures) VALUES(?,?,1)
 ON CONFLICT(account_id) DO UPDATE SET failures=CASE WHEN window_start+300<=excluded.window_start THEN 1 ELSE failures+1 END,
 window_start=CASE WHEN window_start+300<=excluded.window_start THEN excluded.window_start ELSE window_start END`, id, now.Unix())
	if err != nil {
		return err
	}
	return ErrMFAInvalid
}

// Incorrect proofs commit only their throttle counter. Successful proofs and
// the action they authorize commit together, including single-use recovery codes.
func proofFailure(tx *sql.Tx, err error) error {
	if errors.Is(err, ErrMFAInvalid) {
		if e := tx.Commit(); e != nil {
			return e
		}
	}
	return err
}
func activeRevision(ctx context.Context, tx *sql.Tx, id string, revision int64) error {
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT a.enabled=1 AND a.revision=? AND (a.manager_id IS NULL OR m.enabled=1)
 FROM accounts a LEFT JOIN accounts m ON m.id=a.manager_id WHERE a.id=?`, revision, id).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrCredentialsChanged
	}
	return nil
}
func (s *Store) consumeFactor(ctx context.Context, tx *sql.Tx, id, code string, now time.Time) error {
	if err := attemptAllowed(ctx, tx, id, now); err != nil {
		return err
	}
	var sealed []byte
	var last int64
	err := tx.QueryRowContext(ctx, "SELECT secret,last_step FROM account_totp WHERE account_id=?", id).Scan(&sealed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMFADisabled
	}
	if err != nil {
		return err
	}
	if s.mfaBox == nil {
		return fmt.Errorf("TOTP encryption is unavailable")
	}
	secret, err := s.mfaBox.Decrypt(id, sealed)
	if err != nil {
		return err
	}
	valid := false
	if step, ok := auth.MatchTOTP(secret, code, now, last); ok {
		_, err = tx.ExecContext(ctx, "UPDATE account_totp SET last_step=? WHERE account_id=?", step, id)
		valid = err == nil
	} else if hash, ok := auth.RecoveryHash(id, code); ok {
		var result sql.Result
		result, err = tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE account_id=? AND hash=?", id, hash)
		if err == nil {
			var n int64
			n, err = result.RowsAffected()
			valid = n == 1
		}
	}
	if err != nil {
		return err
	}
	if !valid {
		return failedAttempt(ctx, tx, id, now)
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM mfa_attempts WHERE account_id=?", id)
	return err
}
func (s *Store) VerifyMFA(id string, revision int64, code string, now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = activeRevision(ctx, tx, id, revision); err != nil {
		return err
	}
	if err = s.consumeFactor(ctx, tx, id, code, now); err != nil {
		return proofFailure(tx, err)
	}
	return tx.Commit()
}
func replaceRecovery(ctx context.Context, tx *sql.Tx, id string, codes []string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE account_id=?", id); err != nil {
		return err
	}
	for _, code := range codes {
		hash, ok := auth.RecoveryHash(id, code)
		if !ok {
			return fmt.Errorf("invalid generated recovery code")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO recovery_codes(account_id,hash) VALUES(?,?)", id, hash); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) EnableMFA(id string, revision int64, secret, code string, now time.Time) ([]string, error) {
	if s.mfaBox == nil {
		return nil, fmt.Errorf("TOTP encryption is unavailable")
	}
	codes, err := auth.RecoveryCodes()
	if err != nil {
		return nil, err
	}
	sealed, err := s.mfaBox.Encrypt(id, secret)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = activeRevision(ctx, tx, id, revision); err != nil {
		return nil, err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM account_totp WHERE account_id=?)", id).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("TOTP is already enabled")
	}
	if err = attemptAllowed(ctx, tx, id, now); err != nil {
		return nil, err
	}
	step, ok := auth.MatchTOTP(secret, code, now, -1)
	if !ok {
		return nil, proofFailure(tx, failedAttempt(ctx, tx, id, now))
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO account_totp(account_id,secret,last_step) VALUES(?,?,?)", id, sealed, step); err != nil {
		return nil, err
	}
	if err = replaceRecovery(ctx, tx, id, codes); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM mfa_attempts WHERE account_id=?", id); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE accounts SET revision=revision+1 WHERE id=?", id); err != nil {
		return nil, err
	}
	if err = writeAudit(ctx, tx, AuditRecord{Actor: id, Action: "account.totp.enable", Target: id}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}
func (s *Store) ManageMFA(id, expectedHash, code string, disable bool, now time.Time) ([]string, error) {
	codes, err := auth.RecoveryCodes()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var hash string
	if err = tx.QueryRowContext(ctx, "SELECT password_hash FROM accounts WHERE id=? AND enabled=1", id).Scan(&hash); err != nil {
		return nil, err
	}
	if hash != expectedHash {
		return nil, ErrCredentialsChanged
	}
	if err = s.consumeFactor(ctx, tx, id, code, now); err != nil {
		return nil, proofFailure(tx, err)
	}
	action := "account.recovery-codes.replace"
	if disable {
		_, err = tx.ExecContext(ctx, "DELETE FROM account_totp WHERE account_id=?", id)
		codes = nil
		action = "account.totp.disable"
	} else {
		err = replaceRecovery(ctx, tx, id, codes)
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE accounts SET revision=revision+1 WHERE id=?", id); err != nil {
		return nil, err
	}
	if err = writeAudit(ctx, tx, AuditRecord{Actor: id, Action: action, Target: id}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// Offline only: Open's exclusive process lock requires stopping the daemon.
// No decryption key is needed to remove an inaccessible second factor.
func (s *Store) ResetMFA(login string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id string
	if err = tx.QueryRowContext(ctx, "SELECT id FROM accounts WHERE login=?", login).Scan(&id); err != nil {
		return fmt.Errorf("account not found")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM account_totp WHERE account_id=?", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM mfa_attempts WHERE account_id=?", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE accounts SET revision=revision+1 WHERE id=?", id); err != nil {
		return err
	}
	if err = writeAudit(ctx, tx, AuditRecord{Actor: "local-owner", Action: "account.totp.recover", Target: id}); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) RecordSessionRevocation(actor, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = writeAudit(ctx, tx, AuditRecord{Actor: actor, Action: "account.sessions.revoke", Target: id}); err != nil {
		return err
	}
	return tx.Commit()
}

// The actor proves their OWN credentials, never the target's second factor.
// An administrator can reset only subordinate users; all sessions of the target
// are subsequently revoked by HTTP under the exclusive authentication lock.
func (s *Store) AdminResetMFA(actor, target, expectedHash, proof string, now time.Time) error {
	if actor == target {
		_, err := s.ManageMFA(actor, expectedHash, proof, true, now)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var allowed bool
	var hash string
	err = tx.QueryRowContext(ctx, `SELECT a.password_hash,a.enabled=1 AND (a.role='superadmin' OR (a.role='admin' AND t.role='user' AND t.manager_id=a.id))
 FROM accounts a JOIN accounts t ON t.id=? WHERE a.id=?`, target, actor).Scan(&hash, &allowed)
	if err != nil {
		return err
	}
	if !allowed || hash != expectedHash {
		return ErrCredentialsChanged
	}
	var targetEnabled, actorEnabled bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM account_totp WHERE account_id=?),EXISTS(SELECT 1 FROM account_totp WHERE account_id=?)", target, actor).Scan(&targetEnabled, &actorEnabled); err != nil {
		return err
	}
	if !targetEnabled {
		return ErrMFADisabled
	}
	if actorEnabled {
		if err = s.consumeFactor(ctx, tx, actor, proof, now); err != nil {
			return proofFailure(tx, err)
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM account_totp WHERE account_id=?", target); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM mfa_attempts WHERE account_id=?", target); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE accounts SET revision=revision+1 WHERE id=?", target); err != nil {
		return err
	}
	if err = writeAudit(ctx, tx, AuditRecord{Actor: actor, Action: "account.totp.reset", Target: target}); err != nil {
		return err
	}
	return tx.Commit()
}

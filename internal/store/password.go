package store

import (
	"awg-panel/internal/auth"
	"context"
	"errors"
	"time"
)

var ErrCredentialsChanged = errors.New("credentials changed; sign in again")

// Compare-and-swap prevents overwriting a password changed after verification.
func (s *Store) ReplacePassword(id, expected, password string, proofs ...string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM account_totp WHERE account_id=?)", id).Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		proof := ""
		if len(proofs) > 0 {
			proof = proofs[0]
		}
		if err = s.consumeFactor(ctx, tx, id, proof, time.Now()); err != nil {
			return proofFailure(tx, err)
		}
	}
	result, err := tx.ExecContext(ctx, "UPDATE accounts SET password_hash=?,revision=revision+1 WHERE id=? AND password_hash=? AND enabled=1", hash, id, expected)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrCredentialsChanged
	}
	if err = writeAudit(ctx, tx, AuditRecord{Actor: id, Action: "account.password", Target: id}); err != nil {
		return err
	}
	return tx.Commit()
}

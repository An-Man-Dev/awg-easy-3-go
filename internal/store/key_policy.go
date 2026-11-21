package store

import (
	"awg-panel/internal/model"
	"context"
	"database/sql"
	"fmt"
	"time"
)

func readKeyPolicy(ctx context.Context, tx *sql.Tx) (*model.KeyPolicy, error) {
	var p model.KeyPolicy
	err := tx.QueryRowContext(ctx, "SELECT revision,retain FROM key_policy WHERE id=1").Scan(&p.Revision, &p.Retain)
	if err != nil {
		return nil, err
	}
	return &p, p.Validate()
}
func (s *Store) SaveKeyPolicy(next model.KeyPolicy, expected int64) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if next.Revision != expected+1 {
		return ErrSettingsConflict
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := s.db.ExecContext(ctx, "UPDATE key_policy SET revision=?,retain=? WHERE id=1 AND revision=?", next.Revision, next.Retain, expected)
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
	return nil
}

// DELETE uses the connection's secure_delete and DELETE journal settings. This
// does not erase filesystem snapshots, backups, or previously downloaded files.
func (s *Store) PurgeStoredKeys(revision int64) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	policy, err := readKeyPolicy(ctx, tx)
	if err != nil {
		return 0, err
	}
	if policy.Revision != revision {
		return 0, ErrSettingsConflict
	}
	if policy.Retain {
		return 0, fmt.Errorf("disable key retention before removing stored keys")
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM device_secrets")
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

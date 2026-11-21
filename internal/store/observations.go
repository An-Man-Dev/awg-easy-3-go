package store

import (
	"context"
	"fmt"
	"time"
)

// Observations are local runtime history, deliberately separate from portable state.
func (s *Store) Observations() (map[string]time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, "SELECT device_id,last_handshake FROM device_observations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]time.Time{}
	for rows.Next() {
		var id string
		var seconds int64
		if err := rows.Scan(&id, &seconds); err != nil {
			return nil, err
		}
		result[id] = time.Unix(seconds, 0).UTC()
	}
	return result, rows.Err()
}
func (s *Store) SaveObservations(changed map[string]time.Time) error {
	if len(changed) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for id, last := range changed {
		if last.Unix() <= 0 {
			return fmt.Errorf("invalid handshake time")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO device_observations(device_id,last_handshake) VALUES(?,?)
   ON CONFLICT(device_id) DO UPDATE SET last_handshake=excluded.last_handshake
   WHERE excluded.last_handshake > device_observations.last_handshake`, id, last.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"awg-panel/internal/model"
)

func (s *Store) Load() (model.State, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.State{}, err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx)
	if err != nil {
		return state, err
	}
	return state, tx.Commit()
}
func loadState(ctx context.Context, tx *sql.Tx) (model.State, error) {
	var err error
	state := model.State{Version: 1, Profile: map[string]string{}, Peers: []model.Peer{}}
	var initialized bool
	if err = tx.QueryRowContext(ctx, "SELECT initialized FROM metadata WHERE id=1").Scan(&initialized); err != nil {
		return state, err
	}
	if !initialized {
		return state, fmt.Errorf("database is not initialized")
	}
	state.KeyPolicy, err = readKeyPolicy(ctx, tx)
	if err != nil {
		return state, err
	}
	state.Addresses, err = readAddresses(ctx, tx)
	if err != nil {
		return state, err
	}
	state.Settings, err = readSettings(ctx, tx)
	if err != nil {
		return state, err
	}
	if state.Settings == nil {
		return state, fmt.Errorf("server settings are missing")
	}
	if err = tx.QueryRowContext(ctx, "SELECT private_key,public_key FROM server WHERE id=1").Scan(&state.PrivateKey, &state.PublicKey); err != nil {
		return state, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT name,value FROM awg_profile")
	if err != nil {
		return state, err
	}
	for rows.Next() {
		var name, value string
		if err = rows.Scan(&name, &value); err != nil {
			rows.Close()
			return state, err
		}
		state.Profile[name] = value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return state, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT d.id,d.owner_id,d.name,d.network_group,d.slot,d.enabled,
 COALESCE(s.private_key,''),d.public_key,d.preshared_key,d.created_at,
 (a.enabled=0 OR (a.manager_id IS NOT NULL AND m.enabled=0))
 FROM devices d JOIN accounts a ON a.id=d.owner_id LEFT JOIN accounts m ON m.id=a.manager_id LEFT JOIN device_secrets s ON s.device_id=d.id ORDER BY d.slot`)
	if err != nil {
		return state, err
	}
	for rows.Next() {
		var p model.Peer
		var created string
		err = rows.Scan(&p.ID, &p.OwnerID, &p.Name, &p.Group, &p.Slot, &p.Enabled, &p.PrivateKey, &p.PublicKey, &p.PresharedKey, &created, &p.AccountBlocked)
		if err == nil {
			p.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		}
		if err != nil {
			rows.Close()
			return state, fmt.Errorf("invalid stored device")
		}
		state.Peers = append(state.Peers, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return state, err
	}
	if err = model.Validate(state); err != nil {
		return state, err
	}
	return state, nil
}

func (s *Store) Save(state model.State) error { return s.SaveAudited(state, AuditRecord{}) }
func (s *Store) SaveAudited(state model.State, audit AuditRecord) error {
	if err := model.Validate(state); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var initialized bool
	if err = tx.QueryRowContext(ctx, "SELECT initialized FROM metadata WHERE id=1").Scan(&initialized); err != nil {
		return err
	}
	if !initialized {
		return fmt.Errorf("database is not initialized")
	}
	if err = checkDeviceQuota(ctx, tx, state.Peers); err != nil {
		return err
	}
	if err = saveState(ctx, tx, state); err != nil {
		return err
	}
	if err = writeAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func saveState(ctx context.Context, tx *sql.Tx, state model.State) error {
	if err := model.Validate(state); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO server(id,private_key,public_key) VALUES(1,?,?)
 ON CONFLICT(id) DO UPDATE SET private_key=excluded.private_key,public_key=excluded.public_key`, state.PrivateKey, state.PublicKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM awg_profile"); err != nil {
		return err
	}
	for k, v := range state.Profile {
		if _, err := tx.ExecContext(ctx, "INSERT INTO awg_profile(name,value) VALUES(?,?)", k, v); err != nil {
			return err
		}
	}
	wanted := make(map[string]bool, len(state.Peers))
	for _, p := range state.Peers {
		wanted[p.ID] = true
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM devices")
	if err != nil {
		return err
	}
	var removed []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !wanted[id] {
			removed = append(removed, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range removed {
		if _, err = tx.ExecContext(ctx, "DELETE FROM devices WHERE id=?", id); err != nil {
			return err
		}
	}
	for _, p := range state.Peers {
		_, err = tx.ExecContext(ctx, `INSERT INTO devices(id,owner_id,name,network_group,slot,enabled,public_key,preshared_key,created_at)
  VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,name=excluded.name,
  network_group=excluded.network_group,slot=excluded.slot,enabled=excluded.enabled,public_key=excluded.public_key,
  preshared_key=excluded.preshared_key,created_at=excluded.created_at`,
			p.ID, p.OwnerID, p.Name, p.Group, p.Slot, p.Enabled, p.PublicKey, p.PresharedKey, p.CreatedAt.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
		if p.PrivateKey == "" {
			_, err = tx.ExecContext(ctx, "DELETE FROM device_secrets WHERE device_id=?", p.ID)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO device_secrets(device_id,private_key) VALUES(?,?)
   ON CONFLICT(device_id) DO UPDATE SET private_key=excluded.private_key`, p.ID, p.PrivateKey)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

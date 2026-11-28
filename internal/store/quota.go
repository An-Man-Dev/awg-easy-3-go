package store

import (
	"awg-panel/internal/model"
	"context"
	"database/sql"
	"errors"
)

var ErrDeviceQuota = errors.New("device quota exceeded; remove a device or ask the superadministrator to raise the limit")

func checkDeviceQuota(ctx context.Context, tx *sql.Tx, peers []model.Peer) error {
	rows, err := tx.QueryContext(ctx, "SELECT id,device_limit FROM accounts WHERE role<>'superadmin'")
	if err != nil {
		return err
	}
	limits := map[string]int{}
	for rows.Next() {
		var id string
		var limit int
		if err = rows.Scan(&id, &limit); err != nil {
			rows.Close()
			return err
		}
		limits[id] = limit
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, "SELECT owner_id FROM devices")
	if err != nil {
		return err
	}
	var before []model.Peer
	for rows.Next() {
		var p model.Peer
		if err = rows.Scan(&p.OwnerID); err != nil {
			rows.Close()
			return err
		}
		before = append(before, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if model.CheckDeviceQuotaGrowth(before, peers, limits) != nil {
		return ErrDeviceQuota
	}
	return nil
}

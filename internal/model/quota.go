package model

import "fmt"

const DefaultDeviceLimit = 10
const MaxDeviceLimit = 253

// CheckDeviceQuotaGrowth allows existing devices above a lowered quota, but
// rejects growth beyond it. The superadministrator is absent from limits.
func CheckDeviceQuotaGrowth(before, after []Peer, limits map[string]int) error {
	oldCounts, counts := map[string]int{}, map[string]int{}
	for _, p := range before {
		oldCounts[p.OwnerID]++
	}
	for _, p := range after {
		counts[p.OwnerID]++
	}
	for owner, limit := range limits {
		if counts[owner] > limit && counts[owner] > oldCounts[owner] {
			return fmt.Errorf("device quota exceeded")
		}
	}
	return nil
}

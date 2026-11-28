package portable

import (
	"awg-panel/internal/model"
	"fmt"
	"reflect"
)

// Unlisted objects and settings are kept. Mapping an account does not modify it.
type AccountChoice struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	TargetID string `json:"targetId,omitempty"`
	Login    string `json:"login,omitempty"`
	Password bool   `json:"password"`
	TOTP     bool   `json:"totp"`
}
type DeviceChoice struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	TargetID string `json:"targetId,omitempty"`
	Slot     int    `json:"slot,omitempty"`
}
type Selection struct {
	Settings             []string        `json:"settings"`
	Accounts             []AccountChoice `json:"accounts"`
	Devices              []DeviceChoice  `json:"devices"`
	ClientKeys           bool            `json:"clientKeys"`
	DropIncompatibleKeys bool            `json:"dropIncompatibleKeys"`
	AcceptDisruption     bool            `json:"acceptDisruption"`
}
type MergePlan struct {
	Changes  []string `json:"changes"`
	Warnings []string `json:"warnings"`
}

func Merge(current, incoming Snapshot, selection Selection) (Snapshot, MergePlan, error) {
	plan := MergePlan{Changes: []string{}, Warnings: []string{}}
	fail := func(message string) (Snapshot, MergePlan, error) { return Snapshot{}, plan, fmt.Errorf("%s", message) }
	if err := current.Validate(); err != nil {
		return fail("Current configuration is invalid")
	}
	if err := incoming.Validate(); err != nil {
		return fail("Incoming configuration is invalid")
	}
	out := current
	out.Accounts = append([]Account{}, current.Accounts...)
	out.State.Peers = append([]model.Peer{}, current.State.Peers...)
	settings := *current.State.Settings
	settings.Client = settings.Client.Clone()
	out.State.Settings = &settings
	addresses := *current.State.Addresses
	out.State.Addresses = &addresses
	policy := *current.State.KeyPolicy
	out.State.KeyPolicy = &policy
	out.ClientKeysIncluded = true
	seen := map[string]bool{}
	for _, key := range selection.Settings {
		if seen[key] {
			return fail("Duplicate setting selection")
		}
		seen[key] = true
		switch key {
		case "serverName":
			settings.ServerName = incoming.State.Settings.ServerName
		case "dns":
			settings.Client.DNS = incoming.State.Settings.Client.Clone().DNS
		case "mtu":
			settings.Client.MTU = incoming.State.Settings.Client.MTU
		case "keepalive":
			settings.Client.PersistentKeepalive = incoming.State.Settings.Client.PersistentKeepalive
		case "routes":
			settings.Client.AllowedIPs = incoming.State.Settings.Client.Clone().AllowedIPs
		case "vpnHost":
			addresses.VPNHost = incoming.State.Addresses.VPNHost
		case "panelOrigin":
			addresses.PanelOrigin = incoming.State.Addresses.PanelOrigin
		case "keyPolicy":
			policy.Retain = incoming.State.KeyPolicy.Retain
		case "serverKeys":
			out.State.PrivateKey = incoming.State.PrivateKey
			out.State.PublicKey = incoming.State.PublicKey
		case "awgProfile":
			out.State.Profile = incoming.State.Profile
		default:
			return fail("Unknown server setting")
		}
		detail := key
		switch key {
		case "serverName":
			detail = fmt.Sprintf("Server name: %s → %s", current.State.Settings.ServerName, settings.ServerName)
		case "dns":
			detail = fmt.Sprintf("DNS: %v → %v", current.State.Settings.Client.DNS, settings.Client.DNS)
		case "mtu":
			detail = fmt.Sprintf("MTU: %d → %d", current.State.Settings.Client.MTU, settings.Client.MTU)
		case "keepalive":
			detail = fmt.Sprintf("Keepalive: %d → %d", current.State.Settings.Client.PersistentKeepalive, settings.Client.PersistentKeepalive)
		case "routes":
			detail = fmt.Sprintf("Routes: %v → %v", current.State.Settings.Client.AllowedIPs, settings.Client.AllowedIPs)
		case "vpnHost":
			detail = fmt.Sprintf("VPN endpoint: %s → %s", current.State.Addresses.VPNHost, addresses.VPNHost)
		case "panelOrigin":
			detail = fmt.Sprintf("Panel address: %s → %s", current.State.Addresses.PanelOrigin, addresses.PanelOrigin)
		case "keyPolicy":
			detail = fmt.Sprintf("Retain client keys: %t → %t (existing saved keys kept)", current.State.KeyPolicy.Retain, policy.Retain)
		}
		plan.Changes = append(plan.Changes, "Import setting: "+detail)
	}
	if !reflect.DeepEqual(settings, *current.State.Settings) {
		settings.Revision++
	}
	if !reflect.DeepEqual(addresses, *current.State.Addresses) {
		addresses.Revision++
	}
	if !reflect.DeepEqual(policy, *current.State.KeyPolicy) {
		policy.Revision++
	}
	sourceAccounts := map[string]Account{}
	indices := map[string]int{}
	mapping := map[string]string{}
	for _, a := range incoming.Accounts {
		sourceAccounts[a.ID] = a
	}
	for i, a := range out.Accounts {
		indices[a.ID] = i
	}
	selected := map[string]bool{}
	targets := map[string]bool{}
	for _, choice := range selection.Accounts {
		a, ok := sourceAccounts[choice.ID]
		if !ok || selected[choice.ID] {
			return fail("Unknown or duplicate account selection")
		}
		selected[choice.ID] = true
		target := choice.TargetID
		if target == "" {
			target = a.ID
		}
		index, exists := indices[target]
		switch choice.Action {
		case "map":
			if !exists || out.Accounts[index].Role != a.Role {
				return fail("Account mapping requires an existing account with the same role")
			}
			if choice.Password || choice.TOTP || choice.Login != "" {
				return fail("Mapped accounts cannot import credentials or login")
			}
			mapping[a.ID] = target
			plan.Changes = append(plan.Changes, "Map account "+a.Login+" to "+out.Accounts[index].Login)
			continue
		case "add":
			if exists || target != a.ID || a.Role == "superadmin" {
				return fail("New account ID already exists; choose replace or map")
			}
			if !choice.Password {
				return fail("New accounts require importing their password")
			}
		case "replace":
			if !exists || out.Accounts[index].Role != a.Role {
				return fail("Replace requires an existing account with the same role")
			}
		default:
			return fail("Choose add, replace or map for each selected account")
		}
		if targets[target] {
			return fail("Multiple accounts cannot replace the same target")
		}
		targets[target] = true
		mapping[a.ID] = target
	}
	for _, choice := range selection.Accounts {
		if choice.Action == "map" {
			continue
		}
		a := sourceAccounts[choice.ID]
		a.ID = mapping[a.ID]
		if choice.Login != "" {
			a.Login = choice.Login
		}
		for _, old := range current.Accounts {
			if old.ID != a.ID && old.Login == a.Login {
				return fail("Login already belongs to another account; rename, map or skip: " + a.Login)
			}
		}
		if a.ManagerID != "" {
			if mapped, ok := mapping[a.ManagerID]; ok {
				a.ManagerID = mapped
			}
		}
		if index, exists := indices[a.ID]; exists {
			old := out.Accounts[index]
			if !choice.Password {
				a.PasswordHash = old.PasswordHash
			}
			if !choice.TOTP {
				a.MFA = old.MFA
			}
			out.Accounts[index] = a
		} else {
			if !choice.TOTP {
				a.MFA = nil
			}
			indices[a.ID] = len(out.Accounts)
			out.Accounts = append(out.Accounts, a)
		}
		plan.Changes = append(plan.Changes, fmt.Sprintf("%s account: %s (device limit: %s)", choice.Action, a.Login, quotaLabel(a)))
		if choice.Password {
			plan.Warnings = append(plan.Warnings, "Import password for "+a.Login)
		}
		if choice.TOTP {
			plan.Warnings = append(plan.Warnings, "Replace TOTP and recovery codes for "+a.Login+" (including disabling TOTP if absent)")
		}
	}
	logins := map[string]bool{}
	for _, a := range out.Accounts {
		if logins[a.Login] {
			return fail("Login conflict: " + a.Login + "; rename, map or skip the incoming account")
		}
		logins[a.Login] = true
		if a.Role == "user" {
			index, ok := indices[a.ManagerID]
			if !ok || out.Accounts[index].Role != "admin" {
				return fail("Select or map the managing administrator for " + a.Login)
			}
		}
	}
	sourceDevices := map[string]model.Peer{}
	deviceIndices := map[string]int{}
	for _, p := range incoming.State.Peers {
		sourceDevices[p.ID] = p
	}
	for i, p := range out.State.Peers {
		deviceIndices[p.ID] = i
	}
	selected = map[string]bool{}
	targets = map[string]bool{}
	for _, choice := range selection.Devices {
		p, ok := sourceDevices[choice.ID]
		if !ok || selected[choice.ID] {
			return fail("Unknown or duplicate device selection")
		}
		selected[choice.ID] = true
		target := choice.TargetID
		if target == "" {
			target = p.ID
		}
		index, exists := deviceIndices[target]
		if targets[target] {
			return fail("Multiple devices cannot replace one target")
		}
		targets[target] = true
		if choice.Action == "add" {
			if exists || target != p.ID {
				return fail("Device ID exists; choose replace or skip")
			}
		} else if choice.Action == "replace" {
			if !exists {
				return fail("Device replacement target does not exist")
			}
		} else {
			return fail("Choose add or replace for each selected device")
		}
		p.ID = target
		if owner, ok := mapping[p.OwnerID]; ok {
			p.OwnerID = owner
		}
		if _, ok := indices[p.OwnerID]; !ok {
			return fail("Select or map the owner of device " + p.Name)
		}
		if choice.Slot != 0 {
			p.Slot = choice.Slot
		}
		for _, old := range current.State.Peers {
			if old.ID != p.ID && (old.Slot == p.Slot || old.PublicKey == p.PublicKey) {
				return fail("VPN address/public key already belongs to another device; choose its replacement target or a free address")
			}
		}
		if !selection.ClientKeys {
			p.PrivateKey = ""
		}
		if exists && p.PrivateKey == "" {
			old := out.State.Peers[index]
			if p.PublicKey == old.PublicKey {
				p.PrivateKey = old.PrivateKey
			} else if old.PrivateKey != "" && !selection.DropIncompatibleKeys {
				return fail("Device " + p.Name + " changes its public key; include the matching private key or explicitly allow discarding the incompatible stored key")
			}
		}
		if exists {
			out.State.Peers[index] = p
		} else {
			deviceIndices[p.ID] = len(out.State.Peers)
			out.State.Peers = append(out.State.Peers, p)
		}
		plan.Changes = append(plan.Changes, fmt.Sprintf("%s device: %s → 10.8.0.%d (owner %s)", choice.Action, p.Name, p.Slot, p.OwnerID))
	}
	slots := map[int]bool{}
	keys := map[string]bool{}
	for _, p := range out.State.Peers {
		if slots[p.Slot] || keys[p.PublicKey] {
			return fail("VPN address or public key conflict: " + p.Name + "; choose another address/target or skip this device")
		}
		slots[p.Slot] = true
		keys[p.PublicKey] = true
	}
	if len(selection.Devices) > 0 || seen["serverKeys"] || seen["awgProfile"] {
		if incoming.Requirements != current.Requirements {
			return fail("Device/server identity import requires matching protocol, ports, subnets and IPv6 mode")
		}
	}
	if len(selection.Devices) > 0 && (out.State.PublicKey != incoming.State.PublicKey || !reflect.DeepEqual(out.State.Profile, incoming.State.Profile)) {
		plan.Warnings = append(plan.Warnings, "Imported devices use a different server identity or AWG profile; existing source client profiles will need updating")
	}
	if out.State.PublicKey != current.State.PublicKey || !reflect.DeepEqual(out.State.Profile, current.State.Profile) {
		plan.Warnings = append(plan.Warnings, "Server keys or AWG profile change affects ALL existing devices; client profiles may need updating")
	}
	if len(selection.Devices) > 0 || len(selection.Settings) > 0 || len(selection.Accounts) > 0 {
		plan.Warnings = append(plan.Warnings, "VPN connections may be interrupted; all web sessions will be signed out")
	}
	if len(plan.Changes) == 0 {
		return fail("Select at least one setting, account or device")
	}
	limits := map[string]int{}
	for _, a := range out.Accounts {
		if a.Role != "superadmin" {
			limits[a.ID] = a.DeviceLimit
		}
	}
	if model.CheckDeviceQuotaGrowth(current.State.Peers, out.State.Peers, limits) != nil {
		return fail("Device quota exceeded; import the owner's quota with the account, raise it first, or select fewer devices")
	}
	out.State = out.RuntimeState()
	if err := out.Validate(); err != nil {
		return fail("Selected combination is invalid; check account hierarchy, home access and device parameters")
	}
	return out, plan, nil
}

func quotaLabel(a Account) string {
	if a.Role == "superadmin" {
		return "unlimited"
	}
	return fmt.Sprint(a.DeviceLimit)
}

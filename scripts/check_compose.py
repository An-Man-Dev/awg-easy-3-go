#!/usr/bin/env python3
"""Validate Compose security and merge behavior without contacting the daemon."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
for external in (False, True):
    for ipv6 in (False, True):
        command = ["docker", "compose", "--env-file", ".env.example", "-f", "docker-compose.yml"]
        if external:
            command.extend(["-f", "compose.external.yml"])
        if ipv6:
            command.extend(["-f", "compose.ipv6.yml"])
        document = json.loads(subprocess.check_output(command + ["config", "--format", "json"], cwd=root))
        panel = document["services"]["panel"]
        network = document["networks"]["vpn"]
        assert panel.get("network_mode") != "host" and not panel.get("privileged", False)
        assert panel["read_only"] and panel["cap_drop"] == ["ALL"] and panel["cap_add"] == ["NET_ADMIN"]
        assert network["driver"] == "bridge" and not network.get("internal", False)
        assert network.get("enable_ipv6", False) == ipv6
        subnets = [item["subnet"] for item in network["ipam"]["config"]]
        assert "172.30.88.0/24" in subnets
        assert ("fd42:9::/64" in subnets) == ipv6
        tcp = [port for port in panel["ports"] if port["protocol"] == "tcp"]
        assert len(tcp) == int(external)
        if tcp:
            assert tcp[0]["host_ip"] == "127.0.0.1"
        assert bool(panel["environment"]["AWG_EXTERNAL_PANEL_BIND"]) == external
        mounts = {volume["target"]: volume for volume in panel["volumes"]}
        assert mounts["/app/web"]["read_only"] and mounts["/app/web"]["bind"]["selinux"] == "z"
        assert mounts["/run/secrets/admin-password"]["read_only"]
        assert all("docker.sock" not in str(mount) for mount in mounts.values())
        print(f"PASS: Compose external={external}, IPv6={ipv6}")

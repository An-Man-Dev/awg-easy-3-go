#!/usr/bin/env python3
"""Disposable Docker integration test; never runs install.sh or changes host routes."""
import http.cookiejar
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(*args, input=None, check=True):
    result = subprocess.run(args, cwd=ROOT, input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"Command failed: {' '.join(args[:5])}\n{result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipv6", action="store_true", help="Also test IPv6 tunnels and NAT66 on a dual-stack bridge")
    ipv6 = parser.parse_args().ipv6
    project = f"awg-check-{secrets.token_hex(4)}"
    clients = []
    with tempfile.TemporaryDirectory(prefix="awg-check-") as temporary:
        directory = Path(temporary)
        password = secrets.token_urlsafe(24)
        secret = directory / "password"
        secret.write_text(password)
        secret.chmod(0o600)

        def root_owned(path):
            # Prepare only our temporary fixture. The application retains NET_ADMIN only.
            run("docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
                "--cap-add", "CHOWN", "--security-opt", "no-new-privileges:true",
                "-v", f"{path}:/fixture:Z", "--entrypoint", "chown", "awg-panel:local", "0:0", "/fixture")

        root_owned(secret)
        fixture = directory / "netfixture"
        run("env", "GOCACHE=/tmp/awg-panel-go-cache", "GOMODCACHE=/tmp/awg-panel-go-mod", "CGO_ENABLED=0",
            "go", "build", "-trimpath", "-o", str(fixture), "./scripts/netfixture")
        envfile = directory / "test.env"
        envfile.write_text(
            f"AWG_HOST=192.0.2.1\nAWG_PORT=55182\nAWG_PANEL_PORT=18881\n"
            f"AWG_UDP_PUBLISH_HOST=127.0.0.1\nAWG_IPV6_MODE={'auto' if ipv6 else 'disabled'}\n"
            f"AWG_DOCKER_IPV6_SUBNET=fd42:189::/64\n"
            f"AWG_DOCKER_SUBNET=172.30.189.0/24\nAWG_ADMIN_PASSWORD_PATH={secret}\n")
        compose = ["docker", "compose", "--env-file", str(envfile), "-p", project,
                   "-f", "docker-compose.yml", "-f", "compose.external.yml"]
        if ipv6:
            compose.extend(["-f", "compose.ipv6.yml"])
        base = "http://127.0.0.1:18881"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                            urllib.request.HTTPCookieProcessor(jar))
        csrf = ""

        def api(path, method="GET", body=None, expected=200):
            headers = {"Origin": base, "X-CSRF-Token": csrf}
            payload = None
            if body is not None:
                headers["Content-Type"] = "application/json"
                payload = json.dumps(body).encode()
            request = urllib.request.Request(base + "/api" + path, data=payload,
                                             method=method, headers=headers)
            try:
                response = opener.open(request, timeout=45)
            except urllib.error.HTTPError as error:
                response = error
            raw = response.read()
            if response.code != expected:
                raise AssertionError(f"{method} {path}: HTTP {response.code}, expected {expected}: {raw[:200]!r}")
            return json.loads(raw) if "application/json" in response.headers.get("Content-Type", "") else raw

        def peer_container(peer, server_ip):
            conf = api(f"/peers/{peer['id']}/config").decode()
            conf = re.sub(r"^(Address|DNS|MTU) = .*\n", "", conf, flags=re.M)
            conf = re.sub(r"^Endpoint = .*", f"Endpoint = {server_ip}:55182", conf, flags=re.M)
            path = directory / f"{peer['id']}.conf"
            path.write_text(conf)
            path.chmod(0o600)
            root_owned(path)
            name = f"{project}-{peer['group']}"
            address6 = f"ip -6 address add {peer['address6']}/64 dev awgc nodad && " if ipv6 else ""
            clients.append(name)
            run("docker", "run", "-d", "--name", name, "--network", project + "_vpn",
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                "--read-only", "--tmpfs", "/run", "--tmpfs", "/tmp",
                "--security-opt", "no-new-privileges:true",
                "-v", f"{path}:/client.conf:ro,Z", "-v", f"{fixture}:/netfixture:ro,z",
                "--entrypoint", "sh", "awg-panel:local", "-c",
                "amneziawg-go -f awgc >/tmp/awg.log 2>&1 & "
                "for i in $(seq 1 50); do test -S /run/amneziawg/awgc.sock && break; sleep 0.1; done; "
                "awg setconf awgc /client.conf && "
                f"ip address add {peer['address4']}/24 dev awgc && "
                + address6 +
                "ip link set awgc mtu 1280 up && exec sleep 600")
            return name

        def fetch(name, host="10.8.0.1", port=18881):
            if ":" in host:
                host = f"[{host}]"
            return run("docker", "exec", name, "wget", "-q", "-T", "3", "-O", "/dev/null",
                       f"http://{host}:{port}/", check=False).returncode == 0

        try:
            run(*compose, "up", "-d", "--no-build", "--wait", "--wait-timeout", "90")
            container = run(*compose, "ps", "-q", "panel").stdout.strip()
            inspected = json.loads(run("docker", "inspect", container).stdout)[0]
            assert inspected["HostConfig"]["NetworkMode"] != "host"
            assert inspected["HostConfig"]["ReadonlyRootfs"]
            assert {cap.removeprefix("CAP_") for cap in inspected["HostConfig"]["CapAdd"]} == {"NET_ADMIN"}
            server_ip = inspected["NetworkSettings"]["Networks"][project + "_vpn"]["IPAddress"]
            assert run(*compose, "exec", "-T", "panel", "./awg-panel", "--healthcheck").returncode == 0
            login = api("/login", "POST", {"password": password})
            csrf = login["csrf"]
            assert api("/session")["ipv6"] == ipv6, "Effective IP mode differs from test mode"
            home = api("/peers")[0]
            api("/peers", "POST", {"name": "Integration guest", "group": "guest"}, expected=201)
            guest = next(p for p in api("/peers") if p["group"] == "guest")
            for kind in ("config", "link", "qr"):
                value = api(f"/peers/{home['id']}/{kind}")
                assert value, f"Empty {kind} export"
            home_client = peer_container(home, server_ip)
            guest_client = peer_container(guest, server_ip)
            for _ in range(20):
                if fetch(home_client):
                    break
                time.sleep(.5)
            else:
                raise AssertionError("Home peer cannot reach the panel through the real AWG tunnel")
            assert not fetch(guest_client), "Guest accessed the VPN panel"
            if ipv6:
                assert fetch(home_client, "fd42:8::1"), "Home IPv6 panel is unreachable"
                assert not fetch(guest_client, "fd42:8::1"), "Guest accessed the IPv6 panel"
            # Both clients must really have handshaken; a broken guest tunnel is not isolation.
            for name in clients:
                handshake = run("docker", "exec", name, "awg", "show", "awgc", "latest-handshakes").stdout.split()
                assert len(handshake) >= 2 and int(handshake[1]) > 0, f"No handshake for {name}"
            print("PASS: real AWG handshakes, home panel access, guest panel denial", flush=True)

            # A routed documentation/benchmark address simulates an external server.
            # All route changes below happen INSIDE these disposable containers.
            wan = project + "-wan"
            clients.append(wan)
            address6 = "ip -6 address add 2001:db8:189::2/128 dev lo && " if ipv6 else ""
            run("docker", "run", "-d", "--name", wan, "--network", project + "_vpn",
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--read-only", "--tmpfs", "/tmp",
                "--security-opt", "no-new-privileges:true", "-v", f"{fixture}:/netfixture:ro,z",
                "--entrypoint", "sh", "awg-panel:local", "-c",
                "ip address add 198.18.0.2/32 dev lo && " + address6 +
                "exec /netfixture")
            wan_net = json.loads(run("docker", "inspect", wan).stdout)[0]["NetworkSettings"]["Networks"][project + "_vpn"]
            run(*compose, "exec", "-T", "panel", "ip", "route", "add", "198.18.0.2/32", "via", wan_net["IPAddress"])
            if ipv6:
                run(*compose, "exec", "-T", "panel", "ip", "-6", "route", "add", "2001:db8:189::2/128", "via", wan_net["GlobalIPv6Address"])
            for name in (home_client, guest_client):
                run("docker", "exec", name, "ip", "route", "add", "198.18.0.2/32", "dev", "awgc")
                assert fetch(name, "198.18.0.2", 8080), "IPv4 forwarding/masquerade failed"
                if ipv6:
                    run("docker", "exec", name, "ip", "-6", "route", "add", "2001:db8:189::2/128", "dev", "awgc")
                    assert fetch(name, "2001:db8:189::2", 8080), "IPv6 forwarding/NAT66 failed"
                run("docker", "exec", name, "ip", "route", "add", wan_net["IPAddress"] + "/32", "dev", "awgc")
            assert fetch(home_client, wan_net["IPAddress"], 8080), "Home access to the routed private network failed"
            assert not fetch(guest_client, wan_net["IPAddress"], 8080), "Guest reached a private network"
            run("docker", "exec", "-d", home_client, "/netfixture")
            assert not fetch(guest_client, home["address4"], 8080), "Guest accessed another VPN peer"
            # An existing guest key can be promoted and demoted without restarting clients.
            api(f"/peers/{guest['id']}", "PATCH", {"group": "home"})
            assert fetch(guest_client), "Promoted home device cannot access the panel"
            api(f"/peers/{guest['id']}", "PATCH", {"group": "guest"})
            assert not fetch(guest_client), "Demoted guest retained panel access"
            print("PASS: routed WAN traffic, NAT, private-network/peer isolation, live group changes", flush=True)

            # Changes retain credentials and update the running device configuration.
            original = api(f"/peers/{home['id']}/config")
            api(f"/peers/{guest['id']}", "PATCH", {"enabled": False})
            assert not fetch(guest_client, "198.18.0.2", 8080), "Disabled peer still forwarded traffic"
            api(f"/peers/{guest['id']}", "DELETE")
            assert len(api("/peers")) == 1
            api(f"/peers/{home['id']}", "DELETE", expected=400)

            # Delete only this test container's owned table. Wait for its watchdog.
            run(*compose, "exec", "-T", "panel", "nft", "delete", "table", "inet", "awg_panel")
            assert run(*compose, "exec", "-T", "panel", "./awg-panel", "--healthcheck", check=False).returncode != 0
            for _ in range(30):
                result = run(*compose, "exec", "-T", "panel", "./awg-panel", "--healthcheck", check=False)
                if result.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise AssertionError("Watchdog did not restore the firewall")
            print("PASS: firewall deletion detected and repaired", flush=True)
            assert fetch(home_client), "Home tunnel did not recover after firewall repair"
            if ipv6:
                assert fetch(home_client, "fd42:8::1"), "IPv6 interface address was lost during watchdog repair"
            run(*compose, "restart", "panel")
            for _ in range(40):
                if run(*compose, "exec", "-T", "panel", "./awg-panel", "--healthcheck", check=False).returncode == 0:
                    break
                time.sleep(.5)
            jar.clear()
            csrf = api("/login", "POST", {"password": password})["csrf"]
            assert api(f"/peers/{home['id']}/config") == original, "Restart changed private keys or configuration"
            print("PASS: API lifecycle, exports, last-home protection, persistent keys across restart", flush=True)
            print(run("docker", "stats", "--no-stream", "--format", "Container memory: {{.MemUsage}}", container).stdout.strip(), flush=True)
            print(run(*compose, "exec", "-T", "panel", "sh", "-c",
                      "for f in /proc/[0-9]*/status; do awk '/^Name:|^VmRSS:/ {print}' \"$f\"; done").stdout.strip(), flush=True)
        except Exception:
            print(run(*compose, "logs", "--tail", "60", check=False).stdout, flush=True)
            for name in clients:
                print(name, run("docker", "logs", "--tail", "20", name, check=False).stderr, flush=True)
            raise
        finally:
            for name in clients:
                run("docker", "rm", "-f", name, check=False)
            run(*compose, "down", "--volumes", "--remove-orphans", check=True)


if __name__ == "__main__":
    main()

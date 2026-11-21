#!/usr/bin/env python3
"""Disposable Docker integration test; never runs install.sh or changes host routes."""
import http.cookiejar
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
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
    parser.add_argument("--image", default="awg-panel:local", help="Built runtime image to test")
    parser.add_argument("--fixture", type=Path, help="Prebuilt netfixture binary for servers without Go")
    parser.add_argument("--keys-only", action="store_true", help="Run only retention, one-time issuance and key rotation checks")
    parser.add_argument("--accounts-only", action="store_true", help="Run account scoping, shared home network and inherited VPN suspension checks")
    parser.add_argument("--mfa-only", action="store_true", help="Run TOTP, recovery, restart and offline recovery checks")
    parser.add_argument("--transfer-only", action="store_true", help="Run encrypted migration between two isolated installations")
    args = parser.parse_args()
    if sum((args.accounts_only, args.keys_only, args.mfa_only, args.transfer_only)) > 1:
        parser.error("choose one focused suite")
    ipv6, runtime_image = args.ipv6, args.image
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
                "-v", f"{path}:/fixture:Z", "--entrypoint", "chown", runtime_image, "0:0", "/fixture")

        root_owned(secret)
        fixture = directory / "netfixture"
        if args.fixture:
            shutil.copyfile(args.fixture, fixture)
            fixture.chmod(0o755)
        elif not (args.keys_only or args.mfa_only or args.transfer_only):
            run("env", "GOCACHE=/tmp/awg-panel-go-cache", "GOMODCACHE=/tmp/awg-panel-go-mod", "CGO_ENABLED=0",
                "go", "build", "-trimpath", "-o", str(fixture), "./scripts/netfixture")
        envfile = directory / "test.env"
        envfile.write_text(
            f"AWG_HOST=192.0.2.1\nAWG_PORT=55182\nAWG_PANEL_PORT=18881\n"
            f"AWG_UDP_PUBLISH_HOST=127.0.0.1\nAWG_IPV6_MODE={'auto' if ipv6 else 'disabled'}\n"
            f"AWG_DOCKER_IPV6_SUBNET=fd42:189::/64\nAWG_PUBLIC_ORIGIN=https://192.0.2.9\n"
            f"AWG_DOCKER_SUBNET=172.30.189.0/24\nAWG_ADMIN_PASSWORD_PATH={secret}\n")
        compose = ["docker", "compose", "--env-file", str(envfile), "-p", project,
                   "-f", "docker-compose.yml", "-f", "compose.external.yml"]
        if ipv6:
            compose.extend(["-f", "compose.ipv6.yml"])
        image_override = directory / "image.json"
        override = {"services": {"panel": {"image": runtime_image}}}
        if args.mfa_only or args.transfer_only:
            # The disposable test bridge acts as a proxy so independent browser
            # identities do not share an IP throttle; account throttles still apply.
            override["services"]["panel"]["environment"] = {"AWG_TRUSTED_PROXIES": "172.30.189.0/24"}
        image_override.write_text(json.dumps(override))
        compose.extend(["-f", str(image_override)])
        base = "http://127.0.0.1:18881"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                            urllib.request.HTTPCookieProcessor(jar))
        csrf = ""

        def api(path, method="GET", body=None, expected=200, origin=None):
            headers = {"Origin": origin or base, "X-CSRF-Token": csrf}
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
                raise AssertionError(f"{method} {path}: HTTP {response.code}, expected {expected}")
            return json.loads(raw) if "application/json" in response.headers.get("Content-Type", "") else raw

        def peer_container(peer, server_ip, conf=None, tag=""):
            if conf is None:
                conf = api(f"/peers/{peer['id']}/config").decode()
            conf = re.sub(r"^(Address|DNS|MTU) = .*\n", "", conf, flags=re.M)
            conf = re.sub(r"^Endpoint = .*", f"Endpoint = {server_ip}:55182", conf, flags=re.M)
            path = directory / f"{peer['id']}{tag}.conf"
            path.write_text(conf)
            path.chmod(0o600)
            root_owned(path)
            name = f"{project}-{peer['group']}{tag}"
            address6 = f"ip -6 address add {peer['address6']}/64 dev awgc nodad && " if ipv6 else ""
            clients.append(name)
            run("docker", "run", "-d", "--name", name, "--network", project + "_vpn",
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                "--read-only", "--tmpfs", "/run", "--tmpfs", "/tmp",
                "--security-opt", "no-new-privileges:true",
                "-v", f"{path}:/client.conf:ro,Z",
                *(["-v", f"{fixture}:/netfixture:ro,z"] if not (args.keys_only or args.mfa_only or args.transfer_only) else []),
                "--entrypoint", "sh", runtime_image, "-c",
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
            assert inspected["HostConfig"]["Memory"] == 256 * 1024 * 1024
            assert {cap.removeprefix("CAP_") for cap in inspected["HostConfig"]["CapAdd"]} == {"NET_ADMIN"}
            server_ip = inspected["NetworkSettings"]["Networks"][project + "_vpn"]["IPAddress"]
            assert run(*compose, "exec", "-T", "panel", "./awg-panel", "--healthcheck").returncode == 0
            login = api("/login", "POST", {"password": password})
            csrf = login["csrf"]
            assert api("/session")["ipv6"] == ipv6, "Effective IP mode differs from test mode"
            if args.transfer_only:
                from transfer_checks import check_transfer
                check_transfer(base, password, run, compose, container, runtime_image,
                               server_ip, peer_container, fetch, ipv6, directory, project)
                return
            if args.mfa_only:
                from mfa_checks import check_mfa
                check_mfa(base, password, run, compose, container, runtime_image,
                          server_ip, peer_container, fetch, ipv6, directory)
                return
            if args.accounts_only:
                from account_checks import check_accounts
                def relogin():
                    nonlocal csrf
                    jar.clear()
                    csrf = api('/login', 'POST', {'login': 'admin', 'password': password})['csrf']
                check_accounts(api, base, password, run, compose, container, server_ip,
                               peer_container, fetch, ipv6, relogin)
                return
            home = api("/peers")[0]
            original = api(f"/peers/{home['id']}/config")
            if not args.keys_only:
                api("/peers", "POST", {"name": "Integration guest", "group": "guest"}, expected=201)
                guest = next(p for p in api("/peers") if p["group"] == "guest")
                settings = api("/settings")
                old_version = api(f"/peers/{home['id']}/link")["version"]
                updated = dict(settings, serverName="Integration network", client=dict(settings["client"],
                               dns=["9.9.9.9", "1.1.1.1"], mtu=1360, persistentKeepalive=15))
                saved_settings = api("/settings", "PUT", updated)
                api("/settings", "PUT", updated, expected=409)
                api(f"/peers/{home['id']}/qr?version={old_version}", expected=409)
                for peer in (home, guest):
                    conf = api(f"/peers/{peer['id']}/config").decode()
                    assert "DNS = 9.9.9.9, 1.1.1.1" in conf and "MTU = 1360" in conf
                    assert "PersistentKeepalive = 15" in conf
                assert api("/session")["serverName"] == "Integration network"
                print("PASS: global settings update existing exports; stale edits and mixed QR versions rejected", flush=True)
                addresses = api('/addresses')
                old_export = api(f"/peers/{home['id']}/config").decode()
                saved_addresses = api('/addresses', 'PUT', dict(addresses, vpnHost='192.0.2.2', panelOrigin='https://192.0.2.3'))
                api('/session', expected=401)
                api('/login', 'POST', {'password': password}, expected=403, origin='https://192.0.2.9')
                jar.clear()
                csrf = api('/login', 'POST', {'password': password}, origin='https://192.0.2.3')['csrf']
                assert api(f"/peers/{home['id']}/config").decode() == old_export.replace('192.0.2.1:55182','192.0.2.2:55182')
                rules = run('docker', 'exec', container, 'nft', 'list', 'set', 'inet', 'awg_panel', 'protected4').stdout
                assert '192.0.2.2' in rules and '192.0.2.3' in rules and '192.0.2.9' not in rules
                print('PASS: address changes preserve keys, update endpoint/firewall/origins and revoke sessions', flush=True)

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
                for _ in range(40):
                    activity = {p['id']: p['activity'] for p in api('/peers')}
                    if all(activity[p['id']]['status'] == 'online' for p in (home, guest)):
                        break
                    time.sleep(.5)
                else:
                    raise AssertionError("Live handshakes did not become online statuses")
                assert all(activity[p['id']].get('lastHandshake') for p in (home, guest))
                print("PASS: shared AWG observation reports both real peers online with timestamps", flush=True)


                # A routed documentation/benchmark address simulates an external server.
                # All route changes below happen INSIDE these disposable containers.
                wan = project + "-wan"
                clients.append(wan)
                address6 = "ip -6 address add 2001:db8:189::2/128 dev lo && " if ipv6 else ""
                run("docker", "run", "-d", "--name", wan, "--network", project + "_vpn",
                    "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--read-only", "--tmpfs", "/tmp",
                    "--security-opt", "no-new-privileges:true", "-v", f"{fixture}:/netfixture:ro,z",
                    "--entrypoint", "sh", runtime_image, "-c",
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
                # Recreate with the same data volume and an unavailable bootstrap secret.
                # Established credentials must come from SQLite, not the environment/file.
                image_override.write_text(json.dumps({"services": {"panel": {
                    "image": runtime_image,
                    "environment": {"AWG_PASSWORD_FILE": "/run/missing-bootstrap-secret",
                                    "AWG_PASSWORD": "changed-bootstrap-password"}}}}))
                run(*compose, "up", "-d", "--no-build", "--force-recreate", "--wait", "--wait-timeout", "90")
                container = run(*compose, "ps", "-q", "panel").stdout.strip()
                api("/session", expected=401)
                jar.clear()
                api("/login", "POST", {"password": "changed-bootstrap-password"}, expected=401)
                csrf = api("/login", "POST", {"password": password})["csrf"]
                assert api(f"/peers/{home['id']}/config") == original, "Recreation changed saved configuration"
                modes = run(*compose, "exec", "-T", "panel", "stat", "-c", "%a", "/data", "/data/panel.db").stdout.split()
                assert modes == ["700", "600"], "SQLite directory/file permissions are not private"
                assert run(*compose, "exec", "-T", "panel", "test", "!", "-e", "/data/state.json").returncode == 0
                assert api("/settings") == saved_settings, "Recreation reset global settings"
                assert api("/addresses") == saved_addresses, "Bootstrap environment reset saved addresses"
                retained = next(p for p in api('/peers') if p['id'] == home['id'])
                assert retained['activity'].get('lastHandshake'), "Recreation lost handshake history"

                print("PASS: SQLite volume survives recreation; bootstrap secret ignored; sessions revoked; private files", flush=True)
            # Use a fresh client after recreation, and establish access BEFORE deletion.
            # A stale UDP client from the previous container is not a valid deletion baseline.
            server_ip = json.loads(run('docker', 'inspect', container).stdout)[0]['NetworkSettings']['Networks'][project + '_vpn']['IPAddress']
            purge_client = peer_container(home, server_ip, original.decode(), '-purge-check')
            for _ in range(30):
                if fetch(purge_client):
                    break
                time.sleep(.3)
            else:
                raise AssertionError('Pre-deletion home tunnel is unavailable')
            policy = api('/key-policy')
            policy = api('/key-policy', 'PUT', {'revision': policy['revision'], 'retain': False})
            assert policy['storedKeys'] == 1
            assert api(f"/peers/{home['id']}/config") == original, 'Disabling storage deleted old keys'
            # Export policy deletion must not change server forwarding or existing key material.
            api('/keys/stored', 'DELETE', {'revision': policy['revision'], 'deleteVersion': policy['deleteVersion'], 'confirm': True})
            api(f"/peers/{home['id']}/config", expected=404)
            assert fetch(purge_client), 'Deleting stored private keys broke an existing tunnel'
            issued = api('/peers', 'POST', {'name': 'One-time home', 'group': 'home'}, expected=201)
            assert issued['config'] and issued['link'] and issued['qrFrames'] and not issued['storedPrivateKey']
            transient = next(p for p in api('/peers') if p['id'] == issued['id'])
            for kind in ('config', 'link', 'qr'):
                api(f"/peers/{transient['id']}/{kind}", expected=404)
            # This external test harness alone saves the response to feed a real disposable client.
            # The panel itself must never store this private key.
            ephemeral_client = peer_container(transient, server_ip, issued['config'], '-ephemeral')
            for _ in range(30):
                if fetch(ephemeral_client):
                    break
                time.sleep(.3)
            else:
                raise AssertionError('One-time configuration could not connect')
            rotated = api(f"/peers/{transient['id']}/reissue", 'POST', {'keyVersion': transient['keyVersion'], 'confirm': True})
            assert rotated['config'] != issued['config'] and rotated['id'] == issued['id']
            api(f"/peers/{transient['id']}/reissue", 'POST', {'keyVersion': transient['keyVersion'], 'confirm': True}, expected=409)
            assert not fetch(ephemeral_client), 'Old profile still works after key rotation'
            rotated_client = peer_container(transient, server_ip, rotated['config'], '-rotated')
            for _ in range(30):
                if fetch(rotated_client):
                    break
                time.sleep(.3)
            else:
                raise AssertionError('Reissued profile could not connect')
            if ipv6:
                assert fetch(rotated_client, 'fd42:8::1'), 'Reissued IPv6 profile could not connect'
            key = re.search(r'^PrivateKey = (.+)$', rotated['config'], re.M)[1]
            # Read database bytes without decoding or printing secrets.
            run(*compose, 'stop', 'panel')
            dbcopy = directory / 'retention.db'
            dbcopy.touch(mode=0o600)
            with dbcopy.open('wb') as target:
                subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--volumes-from', container + ':ro', '--entrypoint', 'cat', runtime_image, '/data/panel.db'], stdout=target, check=True)
            import sqlite3
            with sqlite3.connect(dbcopy) as database:
                assert database.execute('SELECT count(*) FROM device_secrets').fetchone()[0] == 0
            assert key.encode() not in dbcopy.read_bytes(), 'One-time private key leaked into SQLite'
            run(*compose, 'up', '-d', '--no-build', '--wait', '--wait-timeout', '90')
            jar.clear()
            csrf = api('/login', 'POST', {'password': password})['csrf']
            assert api('/key-policy')['retain'] is False
            api(f"/peers/{transient['id']}/config", expected=404)
            policy = api('/key-policy')
            api('/key-policy', 'PUT', {'revision': policy['revision'], 'retain': True})
            api(f"/peers/{transient['id']}/config", expected=404)
            saved = api('/peers', 'POST', {'name': 'Stored again', 'group': 'guest'}, expected=201)
            assert saved['storedPrivateKey'] and api(f"/peers/{saved['id']}/config").decode() == saved['config']
            print('PASS: retention, safe deletion, one-time real tunnel, key rotation/revocation, restart and no private keys in SQLite', flush=True)
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

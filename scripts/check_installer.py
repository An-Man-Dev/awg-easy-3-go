#!/usr/bin/env python3
"""Exercise installer control flow with fake Docker/Git and private temp paths.

Never deploys containers or touches /opt. Only the root/TUN preconditions and
installation path are replaced in a temporary script copy; the installer logic,
configuration parser, file writes, update path, and output are executed by bash.
Real Docker/VPN behavior is tested separately by integration_test.py.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="awg-installer-check-") as temp:
        root = Path(temp)
        installed = root / "installed"
        source = (ROOT / "install.sh").read_text()
        for condition in [
            "[[ $EUID == 0 ]] || die 'Run this installer as root.'",
            "[[ -c /dev/net/tun ]] || die '/dev/net/tun is required.'",
        ]:
            assert source.count(condition) == 1, "Installer precondition changed; review harness"
            source = source.replace(condition, ": # precondition omitted in isolated harness")
        source = source.replace("/opt/awg-panel", str(installed))
        template = root / "template"
        template.mkdir()
        (template / "web").mkdir()
        (template / "web/index.html").write_text("test UI")
        (template / "go.mod").write_text("module fixture\n")
        (template / "Dockerfile").write_text("FROM scratch\n")
        (template / "install.sh").write_text(source)
        commands = root / "bin"
        commands.mkdir()
        helper = f"#!{sys.executable}\n" + '''
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['MOCK_LOG'], 'a') as out:
    out.write(json.dumps([name, *args]) + '\\n')
if name == 'git':
    if args[0] == 'clone':
        shutil.copytree(os.environ['MOCK_TEMPLATE'], args[-1])
    elif 'symbolic-ref' in args:
        print('main')
    elif '--is-inside-work-tree' in args:
        print('true')
    else:
        raise SystemExit('Unexpected Git operation')
elif name == 'docker':
    if args[:2] == ['network', 'inspect']:
        raise SystemExit(1)
    if args[:2] == ['image', 'inspect']:
        print('25000000')
    if '--bootstrap' in args:
        print('PRIVATE_BOOTSTRAP_SENTINEL')
elif name == 'ip':
    raise SystemExit(1)
'''
        for name in ["docker", "git", "ip"]:
            path = commands / name
            path.write_text(helper)
            path.chmod(0o700)
        log = root / "commands.jsonl"
        env = {k: v for k, v in os.environ.items() if not k.startswith("AWG_")}
        env.update(PATH=str(commands) + os.pathsep + env["PATH"],
                   MOCK_LOG=str(log), MOCK_TEMPLATE=str(template))
        config = root / "install.conf"
        config.write_text("AWG_HOST=vpn.example.com\nAWG_EXTERNAL_PANEL_BIND=0.0.0.0:8881\n"
                          "AWG_PUBLIC_ORIGIN=https://panel.example.com\nAWG_IPV6_MODE=disabled\n")
        checkout = root / "checkout"
        shutil.copytree(template, checkout)

        def run(path, *args, overrides=None, success=True):
            run_env = dict(env, **(overrides or {}))
            result = subprocess.run(["bash", str(path), *args], env=run_env, cwd=root,
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True)
            assert (result.returncode == 0) == success, "Unexpected installer result: " + result.stderr
            assert "PRIVATE_BOOTSTRAP_SENTINEL" not in result.stdout + result.stderr
            return result.stdout + result.stderr

        initial_output = run(checkout / "install.sh", "--config", str(config))
        password = (installed / "admin-password").read_text()
        assert len(password) >= 12 and password not in initial_output
        assert "--bootstrap" in initial_output, "Explicit export instructions missing"
        assert 'header Strict-Transport-Security "max-age=31536000"' in initial_output
        assert not checkout.exists(), "Production source cleanup did not run"
        assert "mem_limit: 256m" in (installed / "docker-compose.yml").read_text()
        assert (installed / "admin-password").stat().st_mode & 0o777 == 0o600
        state = installed / "data/panel.db"
        state.write_text("PRIVATE_STATE_SENTINEL")

        # Existing releases have no memory setting in their saved config.
        saved = installed / "install.conf"
        saved.write_text("\n".join(line for line in saved.read_text().splitlines()
                                   if not line.startswith("AWG_MEMORY_LIMIT=")) + "\n")
        output = run(installed / "install.sh", "--update")
        assert password not in output and "--bootstrap" not in output
        assert (installed / "admin-password").read_text() == password
        assert state.read_text() == "PRIVATE_STATE_SENTINEL"
        assert "mem_limit: 256m" in (installed / "docker-compose.yml").read_text()
        run(installed / "install.sh", "--update", overrides={"AWG_MEMORY_LIMIT": "512m"})
        assert "mem_limit: 512m" in (installed / "docker-compose.yml").read_text()
        before = saved.read_bytes()
        for value in ["0", "0m", "-1g", "unlimited", "256m\nextra", "1m;false"]:
            run(installed / "install.sh", "--update", overrides={"AWG_MEMORY_LIMIT": value}, success=False)
            assert saved.read_bytes() == before
        run(installed / "install.sh", "--update", overrides={"AWG_PASSWORD": ""}, success=False)
        assert (installed / "admin-password").read_text() == password
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        assert not any(call[0] == "docker" and "--bootstrap" in call for call in calls)
        print("PASS: install/update do not export secrets; explicit export hint; state/password preserved")
        print("PASS: HSTS snippet, memory default/override, old config migration, invalid settings rejected")


if __name__ == "__main__":
    main()

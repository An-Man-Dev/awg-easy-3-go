"""Encrypted migration between disposable installations; no host VPN changes."""
import base64
import json
import secrets
import time
from pathlib import Path
from account_checks import Client
from mfa_checks import otp


def check_transfer(base, password, run, compose, container, image, server_ip,
                   peer_container, fetch, ipv6, directory, project):
    source = Client(base)
    source.headers = {'X-Forwarded-For': '198.51.100.10'}
    source.login('admin', password)
    home = source.api('/peers')[0]
    profile = source.api('/peers/' + home['id'] + '/config').decode()
    original = peer_container(home, server_ip, conf=profile, tag='-source')

    def connected(client):
        for _ in range(20):
            if fetch(client):
                break
            time.sleep(.5)
        else:
            raise AssertionError('Migrated home profile did not connect')
        if ipv6:
            assert fetch(client, 'fd42:8::1'), 'Migrated IPv6 profile failed'

    connected(original)
    manager = source.api('/accounts', 'POST', dict(login='manager', role='admin', enabled=True, password=password), expected=201)
    user = source.api('/accounts', 'POST', dict(login='member', role='user', managerId=manager['id'], enabled=True, password=password), expected=201)
    guest = source.api('/peers', 'POST', dict(ownerId=user['id'], name='Member guest', group='guest'), expected=201)
    for index, login in enumerate(('manager', 'member')):
        actor = Client(base)
        actor.headers = {'X-Forwarded-For': f'198.51.100.{20 + index}'}
        actor.login(login, password)
        for path in ('/transfer', '/transfer/export', '/transfer/preview', '/transfer/import'):
            actor.api(path, 'GET' if path == '/transfer' else 'POST', expected=403)
    update = {k: user[k] for k in ('login', 'role', 'managerId', 'revision')}
    source.api('/accounts/' + user['id'], 'PUT', {**update, 'enabled': False})
    policy = source.api('/key-policy')
    source.api('/key-policy', 'PUT', {'revision': policy['revision'], 'retain': False})
    setup = source.api('/account/totp/setup', 'POST', {'password': password})
    codes = source.api('/account/totp/confirm', 'POST', {'code': otp(setup['secret'])})['recoveryCodes']
    original_accounts = source.api('/accounts')
    archives = []
    for index, include in enumerate((True, False)):
        source.headers = {'X-Forwarded-For': f'198.51.100.{30 + index}'}
        mode = 'password' if include else 'key'
        secret = secrets.token_urlsafe(24) if include else base64.b64encode(secrets.token_bytes(32)).decode()
        data = source.api('/transfer/export', 'POST', dict(currentPassword=password, code=codes[index],
                         includeClientKeys=include, mode=mode, secret=secret))
        assert data[:8] == b'AWGPACK1'
        assert password.encode() not in data and setup['secret'].encode() not in data
        archives.append((include, secret, base64.b64encode(data).decode()))
    run(*compose, 'stop', 'panel')
    run('docker', 'stop', original)

    for include, secret, archive in archives:
        name = project + '-destination'
        try:
            run('docker', 'volume', 'create', name)
            args = ['docker', 'run', '-d', '--name', name, '--network', project + '_vpn',
                    '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun',
                    '--read-only', '--tmpfs', '/run', '--tmpfs', '/tmp', '--memory', '256m',
                    '--security-opt', 'no-new-privileges:true', '--sysctl', 'net.ipv4.ip_forward=1',
                    '-p', '127.0.0.1:18882:18881', '-v', f'{name}:/data',
                    '-v', f'{Path.cwd()}/web:/app/web:ro,z',
                    '-v', f'{directory}/password:/run/secrets/admin-password:ro,z']
            if ipv6:
                args += ['--sysctl', 'net.ipv6.conf.all.forwarding=1', '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0']
            env = dict(AWG_HOST='192.0.2.2', AWG_PORT='55182', AWG_PANEL_PORT='18881',
                       AWG_EXTERNAL_PANEL_BIND='0.0.0.0:18881', AWG_TRUSTED_PROXIES='172.30.189.0/24',
                       AWG_PASSWORD_FILE='/run/secrets/admin-password', AWG_IPV6_MODE='auto' if ipv6 else 'disabled')
            for key, value in env.items():
                args += ['-e', key + '=' + value]
            run(*args, image)
            for _ in range(60):
                if run('docker', 'exec', name, './awg-panel', '--healthcheck', check=False).returncode == 0:
                    break
                time.sleep(.5)
            else:
                raise AssertionError('Fresh destination did not become healthy')
            target = Client('http://127.0.0.1:18882')
            target.headers = {'X-Forwarded-For': '198.51.100.40'}
            # Published port differs from the application port; Origin stays at
            # the allowed internal endpoint for this local HTTP test fixture.
            target.headers['Origin'] = 'http://127.0.0.1:18881'
            target.login('admin', password)
            assert target.api('/transfer')['importAvailable']
            # Populate the destination with conflicting logins and a device.
            old_manager = target.api('/accounts', 'POST', dict(login='manager', role='admin', enabled=True, password=password), expected=201)
            old_user = target.api('/accounts', 'POST', dict(login='member', role='user', managerId=old_manager['id'], enabled=True, password=password), expected=201)
            old_device = target.api('/peers', 'POST', dict(ownerId=old_user['id'], name='Replaced device', group='guest'), expected=201)
            body = dict(archive=archive, secret=secret, currentPassword=password)
            preview = target.api('/transfer/preview', 'POST', body)
            assert preview['current']['accounts'] == 3 and preview['current']['devices'] == 2
            assert old_device['id'] in [d['id'] for d in preview['currentInventory']['devices']]
            summary = preview['summary']
            assert summary['accounts'] == 3 and summary['devices'] == 2
            assert summary['storedKeys'] == (2 if include else 0) and summary['totpAccounts'] == 1
            assert not summary['retainKeys']
            target.api('/transfer/import', 'POST', dict(archive=archive, secret=secret, ticket=preview['ticket'], confirm=True))
            target.api('/session', expected=401)
            assert target.api('/login', 'POST', dict(login='admin', password=password))['mfaRequired']
            # A recovery code consumed before every export remains spent after import.
            target.headers['X-Forwarded-For'] = '198.51.100.41'
            # Login challenges bind the source IP, so create a fresh challenge.
            target.api('/login', 'POST', dict(login='admin', password=password))
            target.api('/login/verify', 'POST', {'code': codes[0]}, expected=401)
            target.csrf = target.api('/login/verify', 'POST', {'code': codes[2]})['csrf']
            assert target.api('/transfer')['importAvailable']
            assert [(a['id'], a['login'], a['role'], a['managerId'], a['enabled']) for a in target.api('/accounts')] == [
                (a['id'], a['login'], a['role'], a['managerId'], a['enabled']) for a in original_accounts]
            peers = {p['id']: p for p in target.api('/peers')}
            assert peers[guest['id']]['accountBlocked'] and peers[guest['id']]['enabled']
            if include:
                assert target.api('/peers/' + home['id'] + '/config').decode() == profile
            else:
                target.api('/peers/' + home['id'] + '/config', expected=404)
            target_ip = json.loads(run('docker', 'inspect', name).stdout)[0]['NetworkSettings']['Networks'][project + '_vpn']['IPAddress']
            moved = peer_container(home, target_ip, conf=profile, tag='-moved-' + str(include))
            connected(moved)
            # Abrupt process loss after committed replacement must preserve imported state.
            run('docker', 'kill', '--signal', 'KILL', name)
            run('docker', 'start', name)
            for _ in range(60):
                if run('docker', 'exec', name, './awg-panel', '--healthcheck', check=False).returncode == 0:
                    break
                time.sleep(.5)
            connected(moved)
            print('RESOURCE:', run('docker', 'stats', '--no-stream', '--format', '{{.MemUsage}}', name).stdout.strip(), flush=True)
            events = run('docker', 'exec', name, 'cat', '/sys/fs/cgroup/memory.events').stdout
            assert 'oom_kill 0' in events, 'OOM during transfer'
            run('docker', 'stop', moved)
            print('PASS: encrypted migration, accounts/MFA, key inclusion=' + str(include) + ', original VPN profile and restart', flush=True)
        finally:
            run('docker', 'rm', '-f', name, check=False)
            run('docker', 'volume', 'rm', name, check=False)

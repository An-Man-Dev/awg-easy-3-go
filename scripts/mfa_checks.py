"""TOTP persistence and recovery checks for an isolated integration-test panel."""
import base64
import hashlib
import hmac
import json
import sqlite3
import struct
import subprocess
import time
from account_checks import Client


def otp(secret):
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}'


def check_mfa(base, password, run, compose, container, image, server_ip,
              peer_container, fetch, ipv6, directory):
    root = Client(base)
    root.headers = {'X-Forwarded-For': '198.51.100.10'}
    root.login('admin', password)
    home = root.api('/peers')[0]
    profile = root.api('/peers/' + home['id'] + '/config').decode()
    vpn = peer_container(home, server_ip, conf=profile, tag='-mfa')
    for _ in range(20):
        if fetch(vpn):
            break
        time.sleep(.5)
    else:
        raise AssertionError('Home VPN baseline failed')
    setup = root.api('/account/totp/setup', 'POST', {'password': password})
    code = otp(setup['secret'])
    codes = root.api('/account/totp/confirm', 'POST', {'code': code})['recoveryCodes']
    assert len(codes) == 10 and root.api('/account/totp')['enabled']
    assert fetch(vpn) and (not ipv6 or fetch(vpn, 'fd42:8::1'))
    assert root.api('/peers/' + home['id'] + '/config').decode() == profile
    print('PASS: TOTP enrollment preserves live VPN and client profiles', flush=True)

    run(*compose, 'stop', 'panel')
    dbcopy = directory / 'mfa-validation.db'
    with dbcopy.open('wb') as target:
        subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                        '--cap-drop', 'ALL', '--volumes-from', container + ':ro',
                        '--entrypoint', 'cat', image, '/data/panel.db'], stdout=target, check=True)
    data = dbcopy.read_bytes()
    assert setup['secret'].encode() not in data
    for value in codes:
        assert value.encode() not in data and value.replace('-', '').encode() not in data
    with sqlite3.connect(dbcopy) as database:
        assert database.execute('SELECT count(*) FROM recovery_codes').fetchone()[0] == 10
        encrypted = database.execute('SELECT secret FROM account_totp').fetchone()[0]
        assert isinstance(encrypted, bytes) and len(encrypted) > 32
    run(*compose, 'up', '-d', '--no-build', '--force-recreate', '--wait', '--wait-timeout', '90')
    container = run(*compose, 'ps', '-q', 'panel').stdout.strip()
    login = Client(base)
    login.headers = {'X-Forwarded-For': '198.51.100.11'}
    assert login.api('/login', 'POST', {'login': 'admin', 'password': password})['mfaRequired']
    login.api('/peers', expected=401)
    # Successful enrollment's code must remain unusable even after recreation.
    login.api('/login/verify', 'POST', {'code': code}, expected=401)
    login.csrf = login.api('/login/verify', 'POST', {'code': codes[0]})['csrf']
    assert login.api('/account/totp')['recoveryRemaining'] == 9
    assert login.api('/peers/' + home['id'] + '/config').decode() == profile
    print('PASS: encrypted SQLite, recovery hashes, persisted factor and replay protection after recreation', flush=True)

    manager = login.api('/accounts', 'POST', {'login': 'manager', 'role': 'admin', 'enabled': True, 'password': password}, expected=201)
    actor = Client(base)
    actor.headers = {'X-Forwarded-For': '198.51.100.12'}
    actor.login('manager', password)
    pending = actor.api('/account/totp/setup', 'POST', {'password': password})
    actor.api('/account/totp/confirm', 'POST', {'code': otp(pending['secret'])})
    login.headers = {'X-Forwarded-For': '198.51.100.13'}
    login.api('/accounts/' + manager['id'] + '/totp', 'DELETE', {'password': password, 'confirm': True}, expected=400)
    login.api('/accounts/' + manager['id'] + '/totp', 'DELETE', {'password': password, 'code': codes[1], 'confirm': True})
    actor.api('/session', expected=401)
    assert not next(a for a in login.api('/accounts') if a['id'] == manager['id'])['totpEnabled']
    assert login.api('/account/totp')['enabled']
    print('PASS: administrative recovery requires actor factor and revokes target sessions only', flush=True)

    # Offline recovery must refuse to touch the live database.
    locked = run('docker', 'exec', container, './awg-panel', '--reset-totp', 'admin', check=False)
    assert locked.returncode != 0
    run(*compose, 'stop', 'panel')
    run(*compose, 'run', '--rm', '-T', '--no-deps', 'panel', '--reset-totp', 'admin')
    run(*compose, 'up', '-d', '--no-build', '--wait', '--wait-timeout', '90')
    restored = Client(base)
    restored.login('admin', password)
    assert not restored.api('/account/totp')['enabled']
    assert restored.api('/account/totp')['recoveryRemaining'] == 0
    assert restored.api('/peers/' + home['id'] + '/config').decode() == profile
    for _ in range(20):
        if fetch(vpn):
            break
        time.sleep(.5)
    else:
        raise AssertionError('VPN did not resume after offline recovery restart')
    if ipv6:
        assert fetch(vpn, 'fd42:8::1')
    print('PASS: offline recovery requires a stopped daemon; password/VPN remain unchanged', flush=True)

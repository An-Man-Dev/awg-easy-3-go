"""Account authorization and real VPN suspension checks for integration_test.py."""
import http.cookiejar
import json
import time
import urllib.error
import urllib.request


class Client:
    def __init__(self, base):
        self.base, self.csrf = base, ''
        self.headers = {}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def api(self, path, method='GET', body=None, expected=200):
        headers = {'Origin': self.base, 'X-CSRF-Token': self.csrf, **self.headers}
        payload = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            payload = json.dumps(body).encode()
        req = urllib.request.Request(self.base + '/api' + path, data=payload, headers=headers, method=method)
        try:
            result = self.opener.open(req, timeout=45)
        except urllib.error.HTTPError as error:
            result = error
        raw = result.read()
        if result.code != expected:
            raise AssertionError(f'{method} {path}: HTTP {result.code}, expected {expected}')
        return json.loads(raw) if 'application/json' in result.headers.get('Content-Type', '') else raw

    def login(self, login, password):
        self.csrf = self.api('/login', 'POST', {'login': login, 'password': password})['csrf']


def check_accounts(api, base, password, run, compose, container, server_ip,
                   peer_container, fetch, ipv6, relogin):
    def create(login, role, manager=''):
        return api('/accounts', 'POST', dict(login=login, role=role, managerId=manager,
            enabled=True, password=password), expected=201)

    def update(account, **changes):
        body = {k: account[k] for k in ('login', 'role', 'managerId', 'enabled', 'revision')}
        body.update(changes)
        return api('/accounts/' + account['id'], 'PUT', body)

    manager = create('manager-one', 'admin')
    manager2 = create('manager-two', 'admin')
    user = create('user-one', 'user', manager['id'])
    user2 = create('user-two', 'user', manager2['id'])
    admin, owner, other = (Client(base) for _ in range(3))
    admin.login(manager['login'], password)
    owner.login(user['login'], password)
    other.login(user2['login'], password)
    assert len(admin.api('/accounts')) == 2 and len(owner.api('/accounts')) == 1
    own = owner.api('/peers', 'POST', {'name': 'Owned home', 'group': 'home'}, expected=201)
    second = other.api('/peers', 'POST', {'name': 'Other home', 'group': 'home'}, expected=201)
    managed = admin.api('/peers', 'POST', {'name': 'Manager home', 'group': 'home'}, expected=201)
    paused = owner.api('/peers', 'POST', {'name': 'Paused guest', 'group': 'guest'}, expected=201)
    owner.api('/peers/' + paused['id'], 'PATCH', {'enabled': False})
    assert {p['id'] for p in admin.api('/peers')} == {own['id'], managed['id'], paused['id']}
    assert {p['id'] for p in owner.api('/peers')} == {own['id'], paused['id']}
    for client in (owner, admin):
        for kind in ('config', 'link', 'qr'):
            client.api('/peers/' + second['id'] + '/' + kind, expected=404)
        for path in ('/settings', '/addresses', '/key-policy', '/audit'):
            client.api(path, expected=403)
        client.api('/peers/' + second['id'], 'DELETE', expected=404)
    peers = {p['id']: p for p in api('/peers')}
    clients = {p['id']: peer_container(peers[p['id']], server_ip, conf=p['config'], tag='-' + str(i))
               for i, p in enumerate((own, second, managed))}
    for name in clients.values():
        for _ in range(20):
            if fetch(name):
                break
            time.sleep(.5)
        else:
            raise AssertionError('Account home tunnel did not connect')
        if ipv6:
            assert fetch(name, 'fd42:8::1'), 'Account IPv6 tunnel did not connect'
    # Home is deliberately shared between owners; ownership is an API boundary.
    run('docker', 'exec', '-d', clients[second['id']], '/netfixture')
    assert fetch(clients[own['id']], peers[second['id']]['address4'], 8080), 'Shared home IPv4 network broken'
    if ipv6:
        assert fetch(clients[own['id']], peers[second['id']]['address6'], 8080), 'Shared home IPv6 network broken'
    print('PASS: owner-scoped accounts, issuance, exports and management; shared home IPv4/IPv6', flush=True)

    manager = update(manager, enabled=False)
    owner.api('/session', expected=401)
    admin.api('/session', expected=401)
    for p in (own, managed):
        assert not fetch(clients[p['id']]), 'Suspended account retained IPv4 VPN access'
        if ipv6:
            assert not fetch(clients[p['id']], 'fd42:8::1'), 'Suspended account retained IPv6 VPN access'
    assert fetch(clients[second['id']]), 'Unrelated owner lost VPN access'
    assert all(p['accountBlocked'] for p in api('/peers') if p['ownerId'] in (manager['id'], user['id']))
    assert len(run('docker', 'exec', container, 'awg', 'show', 'awg0', 'peers').stdout.split()) == 2
    run(*compose, 'restart', 'panel')
    for _ in range(60):
        if run('docker', 'exec', container, './awg-panel', '--healthcheck', check=False).returncode == 0:
            break
        time.sleep(.5)
    else:
        raise AssertionError('Restart healthcheck failed')
    relogin()
    assert not fetch(clients[own['id']]), 'Restart restored blocked VPN'
    assert len(run('docker', 'exec', container, 'awg', 'show', 'awg0', 'peers').stdout.split()) == 2
    manager = next(a for a in api('/accounts') if a['id'] == manager['id'])
    manager = update(manager, enabled=True)
    for p in (own, managed):
        for _ in range(15):
            if fetch(clients[p['id']]):
                break
            time.sleep(.5)
        else:
            raise AssertionError('Unblocking did not restore an enabled device')
    paused_view = next(p for p in api('/peers') if p['id'] == paused['id'])
    assert not paused_view['enabled'] and not paused_view['accountBlocked']
    assert len(run('docker', 'exec', container, 'awg', 'show', 'awg0', 'peers').stdout.split()) == 4
    owner.api('/session', expected=401)
    print('PASS: inherited web/VPN suspension survives restart; unblock restores only enabled devices', flush=True)

    # Moving the account changes management scope without rotating device profiles.
    original = api('/peers/' + own['id'] + '/config')
    user = update(user, managerId=manager2['id'])
    assert api('/peers/' + own['id'] + '/config') == original
    assert fetch(clients[own['id']]), 'Account transfer changed working VPN identity'
    entries = api('/audit')
    assert any(e['action'] == 'device.create' and e['actor'] == user['id'] for e in entries)
    assert all(set(e) == {'id', 'at', 'actor', 'action', 'target'} for e in entries)
    assert password not in json.dumps(entries)
    print('PASS: account transfer preserves profiles; transactional audit contains metadata only', flush=True)

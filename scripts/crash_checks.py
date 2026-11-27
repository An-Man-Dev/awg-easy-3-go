#!/usr/bin/env python3
"""Crash at network-apply boundaries in disposable Docker containers only."""
import argparse
import concurrent.futures
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
from account_checks import Client


def run(*args, check=True, input=None):
    p = subprocess.run(args, input=input, text=True, capture_output=True)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr}')
    return p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='awg-panel:stabilization')
    args = parser.parse_args()
    name = 'awg-crash-' + secrets.token_hex(5)
    image = name + ':fixture'
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix=name) as tmp:
        d = Path(tmp)
        password = secrets.token_urlsafe(32)
        (d/'password').write_text(password)
        (d/'password').chmod(0o600)
        # Preserve stdin for nft -f; wrappers pause only during explicitly armed calls.
        (d/'wrapper').write_text('''#!/bin/sh
name=${0##*/}
phase=$(cat /run/crash.arm 2>/dev/null || true)
pause() {
 touch /run/crash.ready
 while :; do sleep 1; done
}
if [ "$name" = nft ] && [ "$1" = -f ] && [ "$phase" = before-nft ]; then pause; fi
"/usr/local/libexec/$name.real" "$@" || exit $?
if [ "$name" = nft ] && [ "$1" = -f ] && [ "$phase" = after-nft ]; then pause; fi
if [ "$name" = awg ] && [ "$1" = syncconf ] && [ "$phase" = after-awg ]; then pause; fi
''')
        (d/'Dockerfile').write_text('''ARG BASE
FROM ${BASE}
RUN mkdir -p /usr/local/libexec && cp "$(command -v nft)" /usr/local/libexec/nft.real && cp "$(command -v awg)" /usr/local/libexec/awg.real
COPY wrapper /usr/local/bin/nft
COPY wrapper /usr/local/bin/awg
RUN chmod 755 /usr/local/bin/nft /usr/local/bin/awg
''')
        try:
            run('docker','build','--build-arg','BASE='+args.image,'-t',image,str(d))
            run('docker','run','--rm','--network','none','--cap-drop','ALL','--cap-add','CHOWN',
                '-v',f'{d}/password:/fixture:Z','--entrypoint','chown',image,'0:0','/fixture')
            run('docker','network','create',name)
            run('docker','volume','create',name)
            run('docker','run','-d','--name',name,'--network',name,
                '--cap-drop','ALL','--cap-add','NET_ADMIN','--device','/dev/net/tun',
                '--read-only','--tmpfs','/run','--tmpfs','/tmp','--memory','256m',
                '--security-opt','no-new-privileges:true','--sysctl','net.ipv4.ip_forward=1',
                '-p','127.0.0.1::8881','-v',f'{name}:/data',
                '-v',f'{root}/web:/app/web:ro,z','-v',f'{d}/password:/run/secrets/admin-password:ro,z',
                '-e','AWG_PASSWORD_FILE=/run/secrets/admin-password','-e','AWG_HOST=192.0.2.1',
                '-e','AWG_EXTERNAL_PANEL_BIND=0.0.0.0:8881','-e','AWG_IPV6_MODE=disabled',image)

            def healthy():
                for _ in range(60):
                    if run('docker','exec',name,'./awg-panel','--healthcheck',check=False).returncode == 0:
                        return
                    time.sleep(.25)
                raise AssertionError('Recovery did not become healthy')

            def login():
                port = run('docker','port',name,'8881/tcp').stdout.strip()
                client = Client('http://'+port)
                client.headers = {'Origin':'http://127.0.0.1:8881'}
                client.login('admin',password)
                return client

            healthy()
            for phase in ('before-nft','after-nft','after-awg'):
                client = login()
                previous_keys = set(run('docker','exec',name,'awg','show','awg0','peers').stdout.split())
                peer = client.api('/peers','POST',{'name':phase,'group':'guest'},expected=201)
                added_keys = set(run('docker','exec',name,'awg','show','awg0','peers').stdout.split()) - previous_keys
                assert len(added_keys) == 1, 'Expected one new peer'
                run('docker','exec','-i',name,'sh','-c','cat > /run/crash.arm',input=phase)
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(client.api,'/peers/'+peer['id'],'PATCH',{'enabled':False})
                    for _ in range(100):
                        if run('docker','exec',name,'test','-f','/run/crash.ready',check=False).returncode == 0:
                            break
                        if pending.done():
                            raise AssertionError('Apply finished before crash barrier')
                        time.sleep(.02)
                    else:
                        raise AssertionError('Crash barrier was not reached')
                    # The process must not report success while network apply is incomplete.
                    assert not pending.done()
                    run('docker','kill','--signal','KILL',name)
                    try:
                        pending.result()
                    except Exception:
                        pass
                    else:
                        raise AssertionError('Interrupted request returned success')
                run('docker','start',name)
                healthy()
                client = login()
                saved = next(p for p in client.api('/peers') if p['id']==peer['id'])
                assert not saved['enabled'], 'Committed disable lost'
                # Public keys only: do not read or print AWG private configuration.
                active = run('docker','exec',name,'awg','show','awg0','peers').stdout.split()
                assert not added_keys.intersection(active), 'Disabled peer remained active'
                assert not json.loads(run('docker','inspect',name).stdout)[0]['State']['OOMKilled']
                print('PASS:',phase,'crash, durable disable, network recovery',flush=True)
        finally:
            run('docker','rm','-f',name,check=False)
            run('docker','volume','rm',name,check=False)
            run('docker','network','rm',name,check=False)
            run('docker','image','rm',image,check=False)


if __name__ == '__main__':
    main()

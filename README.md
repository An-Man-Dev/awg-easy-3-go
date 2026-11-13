# AWG Panel

A small, self-hosted Go control plane for native AmneziaWG 3.x, with an external
Vanilla JavaScript admin interface. The panel supervises the official userspace
AWG engine, manages peers, and owns one isolated nftables table inside its Docker
network namespace. No Node.js, frontend build, database server, or embedded web
assets are required.

This is an independent, non-commercial hobby project, created for fun and
learning. It is not affiliated with, sponsored by, or endorsed by Amnezia or the
AmneziaVPN team. References to AmneziaVPN and AmneziaWG describe compatibility
with their software; they do not imply an official relationship.

The project includes standalone Docker Compose files and automated unit and
container integration tests. The native VPN engine is a separate process; its
memory is additional to panel memory. Periodic firewall checks necessarily cause
brief CPU activity every 20 seconds. See the Build and test section for
reproducible checks and the limits of the current validation.

## Source layout

```text
cmd/awg-panel/       Process supervision, listeners, local health/bootstrap CLI
internal/config/    Environment validation and installation settings
internal/model/     State schema, key generation, AWG profile validation
internal/store/     Exclusive state lock and durable atomic writes
internal/artifact/  Native configuration and official compressed vpn:// exports
internal/network/   Routes, interface management, atomic nftables reconciliation
internal/service/   Serialized device mutations and fail-closed recovery
internal/httpapi/   Sessions, CSRF, login limits, API, disk-backed static files
web/                English UI; no build step or remote dependencies
install.sh          Production, development, and update workflows
docker-compose.yml  Standalone installation on a dedicated bridge network
compose.external.yml Optional localhost-only administration port publication
compose.ipv6.yml    Optional dual-stack Docker bridge
scripts/           Disposable container integration tests
```

The supplied legacy reference directory `awg-easy-3/`, when present locally, is
excluded from Git and Docker builds. It is not distributed with this repository
or imported or executed by this application.

## License

The original code, UI, scripts, tests, and documentation in this repository are
licensed under the [MIT License](LICENSE). Third-party components retain their
own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The MIT license
does not replace the licensing obligations of components included in Docker images.
The project's non-commercial purpose is a statement of intent, not an additional
license restriction: the MIT License also permits commercial use by others.

## Acknowledgements

Thank you to the authors and contributors of:

- [alexsemenovru/awg-easy-3](https://github.com/alexsemenovru/awg-easy-3), which
  inspired this project and served as a reference for AWG 3 interoperability.
- [JohnnyVBut/awg-easy](https://github.com/JohnnyVBut/awg-easy), the upstream
  project from which `alexsemenovru/awg-easy-3` was forked.
- [AmneziaVPN and the AmneziaWG projects](https://github.com/amnezia-vpn), whose
  protocol implementations and tools make this application possible.

This project follows that work with its own Go implementation and architecture,
rather than maintaining a direct code fork of either web panel. These credits
acknowledge inspiration and technical references; they do not imply endorsement
or change the licenses of the referenced projects.

## Requirements

- A Linux host with Docker Engine, Compose v2 supporting `up --wait`, nftables
  support in the host kernel, and `/dev/net/tun`.
- Root for installation; Bash 4.3+, Git, iproute2, util-linux (`flock`), and GNU
  coreutils/findutils. The installer does not install host dependencies.
- An unused `172.30.88.0/24` bridge subnet. IPv6 additionally uses `fd42:9::/64`.
  Adjust the generated network and trusted proxy settings if those ranges conflict.
- The configured UDP port open on the host/provider firewall. IPv6 needs a working
  host IPv6 route and Docker IPv6 bridge masquerading support.
- An AmneziaVPN/AmneziaWG client supporting the exported AWG 3.x parameters.

The container uses only `NET_ADMIN`, drops other capabilities, uses a read-only
root filesystem, and mounts `/run` and `/tmp` as bounded tmpfs filesystems. It does
not mount the Docker socket or use host networking. The host firewall is not
rewritten by the panel.

## Installation

### Standalone Compose, including Fedora

The root `docker-compose.yml` can be used directly, without `install.sh`, deleting
sources, or writing to `/opt`. It creates a project-specific bridge network and
named data volume. No host networking, privileged container, Docker socket mount,
or host routing/sysctl changes are requested. Docker manages its own normal
bridge/NAT rules. The bridge must permit egress for VPN clients, so it deliberately
does not use `internal: true` (which disables external connectivity).

Prepare a configuration and a root-owned password file. The password must contain
12–256 bytes. Root ownership matters because `cap_drop: ALL` removes the ability
to bypass another user's mode `0600` file permissions:

```sh
cp .env.example .env
# Edit .env and set AWG_HOST to your reachable public IP or domain.
install -d -m 700 secrets
read -r -s -p 'Admin password: ' AWG_SETUP_PASSWORD
printf '\n'
printf '%s' "$AWG_SETUP_PASSWORD" | sudo tee secrets/admin-password >/dev/null
unset AWG_SETUP_PASSWORD
sudo chown root:root secrets/admin-password
sudo chmod 600 secrets/admin-password
docker compose up -d --build --wait
docker compose exec -T panel ./awg-panel --bootstrap
```

The base configuration publishes only the VPN UDP port. To enable administration
through a host reverse proxy or localhost during development:

```sh
docker compose -f docker-compose.yml -f compose.external.yml up -d --build --wait
```

The additional TCP port binds only to `127.0.0.1`; the container listens on its
bridge interface and still serves internal VPN addresses. Use
`http://127.0.0.1:8881` for local administration. For Caddy, also configure
`AWG_PUBLIC_ORIGIN` and `AWG_TRUSTED_PROXIES` in `.env`. With the default bridge,
the host gateway is `172.30.88.1/32`; adapt this if changing the bridge subnet.
Removing `compose.external.yml` from the invocation removes external access on
the next recreate. Keep the same file list for subsequent Compose commands.

When the Docker host has working IPv6 egress, append `-f compose.ipv6.yml` to the
invocation. This preserves the IPv4 bridge subnet and adds an IPv6 subnet, ULA
client addresses, and NAT66 when the daemon detects routing. On an IPv4-only
host, use the base file. Bridge routes alone do not prove upstream IPv6 Internet
reachability; check this on the deployment host.

For local development, set `AWG_UDP_PUBLISH_HOST=127.0.0.1` to avoid exposing VPN
UDP traffic to the LAN. Production defaults to `0.0.0.0`. The published UDP port
matches `AWG_PORT`, ensuring exported endpoint ports remain correct.

Fedora bind mounts have explicit SELinux labels (`z` for shared read-only web
assets and `Z` for the private password). Named volumes are Docker-managed.
Neither Compose nor the installer disables SELinux or firewalld. A VPN on a
remote server also needs the corresponding UDP port permitted by its firewall;
the local test uses localhost and does not change firewalld settings. Rootless
Docker and an enforcing SELinux device policy need separate validation; the
current integration suite targets a rootful Docker daemon with `/dev/net/tun`.

### Managed server installation

The installer fetches production updates from
`https://github.com/An-Man-Dev/awg-easy-3-go.git`, branch `main`. Development is
maintained on `dev`; production installation/update requires a published `main`
branch. Fork maintainers should change `REPO_URL` in `install.sh`. Private
repositories require suitable Git authentication on the deployment host.

On a production clone on `main`:

```sh
sudo ./install.sh
# Or:
sudo ./install.sh --config /path/to/install.conf
```

The installer reads an explicit config, otherwise local `install.conf`, local
`.env`, or saved `/opt/awg-panel/install.conf`, in that order. Existing environment
variables override file values. Missing values are prompted on a terminal; in
noninteractive use defaults are applied, `AWG_HOST` is required, and an absent
password is generated and printed. To pass environment values through sudo, use
your system's supported environment-preservation mechanism.

Configuration is literal `KEY=value`, with optional matching outer quotes.
Shell expressions and inline comments are not evaluated. See
`install.conf.example`. The saved config and password file are mode `0600` under
a mode `0700` installation directory. The password is mounted as a read-only
secret file, not inserted in the container environment or command arguments.

**Production cleanup is destructive by design:** after successful installation,
the entire dedicated source directory is deleted, including untracked files.
This applies to `main` and directories outside Git. Do not run production
installation from a directory containing unrelated data. The script rejects
system directories, the home directory, and installation ancestors. It also runs
the requested Docker image and builder prune commands, affecting unused caches
across the host.

The installer prints the first home device's `.conf` and `vpn://` link. Import it,
connect, then open `http://10.8.0.1:8881` (or your chosen panel port). Initial state
creates this device once; later installations preserve its keys and all peers.
Export again from the host if necessary:

```sh
cd /opt/awg-panel
sudo docker compose exec -T panel ./awg-panel --bootstrap
```

Treat that terminal output as a secret. The CLI uses a mode `0600` Unix control
socket inside the container; there is no unauthenticated TCP bootstrap endpoint.

## Development and updates

On `dev`, any other non-`main` branch, or a detached HEAD, `install.sh` builds the
current local working tree and prints:

```text
Development branch detected, skipping source cleanup
```

It deploys the image and UI but never deletes the source tree or replaces the
installed `/opt/awg-panel/install.sh`. Development therefore deploys to the same
local installation path intentionally; it is not a separate staging environment.

For production updates:

```sh
sudo /opt/awg-panel/install.sh --update
```

The installed settings are loaded; `main` is cloned into `/tmp/awg-build-XXXXXX`.
All compilation happens in Docker builder stages. A complete UI release is copied
under `releases/`, then the `web` symlink is replaced atomically and the container
is recreated so its read-only bind mount sees the new release. The installer
waits for Docker health before updating the installed script. Temporary source
is removed by an EXIT trap. `/data/state.json` is never migrated or overwritten
by the installer. Old UI releases are retained for manual rollback.

If deployment fails, the previous UI symlink is restored. This is not a complete
image/config rollback: inspect Docker logs, correct the settings, and rerun the
installer. Keys remain on the data volume. An IPv6 bridge mode change requires
network recreation and briefly interrupts all connections.

## Panel access and Caddy

Internal access is always available to enabled `home` peers on `10.8.0.1` and,
when enabled, `fd42:8::1`. `guest` peers cannot reach any local container service,
other VPN peers, private/link-local networks, the server's resolved public
addresses, or panel ports. These checks precede connection-tracking acceptance,
so disabling a device or changing its group also revokes existing flows.

An empty `AWG_EXTERNAL_PANEL_BIND` disables external listening and omits Docker
TCP port publication. To enable a host Caddy reverse proxy:

```ini
AWG_EXTERNAL_PANEL_BIND=0.0.0.0:8881
AWG_EXTERNAL_PANEL_PUBLISH=127.0.0.1:8881
AWG_PUBLIC_ORIGIN=https://panel.example.com
AWG_TRUSTED_PROXIES=172.30.88.1/32
```

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:8881
}
```

Re-run the installer to apply settings. Caddy must preserve the original Host
and provide the standard forwarded headers. Only configured trusted proxy CIDRs
may supply the client address and HTTPS indication. X-Forwarded-For is walked
from the right until the first untrusted hop. Never trust an arbitrary network.
Use the backend's actual source address if your Docker platform presents a
different gateway. Untrusted headers are ignored.

When an IPv4 wildcard external bind uses the internal port, one listener covers
both destinations. Otherwise the panel opens separate listeners. Firewall rules
and request source checks enforce the access distinction in either case. IPv6
binds use explicit `tcp6` listeners only when IPv6 is active.

Public server and proxy DNS addresses are resolved at startup to prevent guest
hairpin access. Restart after changing these DNS records. Do not add an additional
proxy hostname without adding it as the configured public origin. Application
authentication is still required on every administration path.

## IPv6 modes

| Mode | Behavior |
| --- | --- |
| `auto` | Enable IPv6 only when host and container routing are available. |
| `nat66` | Request NAT66; fall back to IPv4 with an English log message if unavailable. |
| `disabled` | No IPv6 interface address, listener, nftables address set, DNS, or client route. |

Both active modes assign `fd42:8::/64`, masquerade it onto the detected IPv6 WAN
interface, and export `::/0` with IPv6 DNS. WAN interfaces are obtained from route
lookups; IPv4 and IPv6 may use different interfaces. No interface named `eth0` is
assumed. IPv4 uses `10.8.0.0/24` with up to 253 peers.

IPv6 capability is fixed for the life of a process so exported profiles and
listeners agree. Loss of an active route makes the daemon stop forwarding and
restart; startup re-detects connectivity. Re-export client profiles if the
effective IP mode changes. IPv4-only exports do not suppress a device's own
non-VPN IPv6 connection; enforce that separately on clients needing a strict
full-device kill switch.

## State, profiles, and recovery

State contains server/client private keys, preshared keys, the AWG profile, and
device metadata. Keep `/opt/awg-panel/data` private and back it up securely.
Every committed mutation uses `write temporary file → fsync → rename → directory
fsync`; an exclusive lock prevents concurrent writers. A malformed existing
state stops startup instead of silently generating new identities.

The durable state is authoritative. A save or network-apply failure stops the
VPN interface and exits. Docker's restart policy reapplies persisted state.
Peer mutations are serialized and briefly lower the interface while firewall
and peer changes are installed. At least one enabled home peer is required.

The default AWG 3 profile enables a random 32-byte header protection key, all four
padding fields, timing ranges, content padding, and a signature packet. All
requested fields are represented: `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`,
`I1`–`I5`, `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`,
`RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`,
`RandomTrailers`, and `DisableCookies`. Optional unused `I2`–`I5` are omitted.
Random trailers default to `off`; cookies remain enabled.

Advanced profile edits are intentionally offline: stop the container, back up
`state.json`, edit its `profile` map using native AWG key names and string values,
then start it and re-export all clients. Validation rejects overlapping headers,
invalid keys, unsafe packet sizes, and invalid timing ranges. Supported signature
tags are `b`, `r`, `rc`, `rd`, and `dz`, bounded to 1280 bytes per packet. This is a
conservative configuration surface, not an unbounded native-UAPI pass-through.

Every 20 seconds the watchdog checks routes and the complete normalized JSON of
the owned nftables table, including hooks, policies, sets, rules, and NAT. Changed
or missing rules trigger one atomic table replacement. It never flushes the
global ruleset. There is necessarily a detection window after external rule
deletion; periodic repair cannot guarantee uninterrupted isolation during that
window. HTTP source checks provide an additional guard for direct panel access.

Session tokens and CSRF secrets use cryptographic randomness. Cookies are
HttpOnly and SameSite=Strict; trusted HTTPS requests also receive Secure cookies.
Mutations require an allowed Origin and matching CSRF header. Login has bounded
per-IP and global token buckets, a single concurrent password derivation, and
PBKDF2-SHA256 verification. Sessions expire after 12 hours or daemon restart.
Static files are read through a confined filesystem root and an explicit asset
allowlist, with ETags and revalidation. API responses and exports are not cached.

## Export and API

Each device has a `.conf` download, a compressed official `vpn://` link, and a
series of server-generated PNG QR codes in AmneziaVPN's native QR format.
Keep the scanner inside AmneziaVPN open until it has read every frame; the panel
cycles through them automatically and also provides pause/previous/next controls.
QR frames use Qt QDataStream framing and 850-byte chunks, matching the official
exporter. They are distinct from clipboard links and AmneziaWG's native `.conf`
QR format. Share artifacts contain private keys. The official Qt codec and AWG parser references are listed in
`THIRD_PARTY_NOTICES.md`.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/login` | Password login; allowed Origin required |
| GET | `/api/session` | CSRF token, endpoint, effective IP mode |
| POST | `/api/logout` | End the current session |
| GET / POST | `/api/peers` | List or create devices |
| PATCH / DELETE | `/api/peers/{id}` | Update or remove a device |
| GET | `/api/peers/{id}/config` | Download native configuration |
| GET | `/api/peers/{id}/link` | Export compressed URI and `qrParts` count |
| GET | `/api/peers/{id}/qr?part=0` | Export a PNG QR frame (zero-based index; default 0) |

All routes except login require a session. Mutation JSON rejects unknown fields
and is limited to 8 KiB. No private keys appear in device list responses.

## Build and test

```sh
go test -race -cover ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/awg-panel ./cmd/awg-panel
docker compose --env-file .env.example build
python3 scripts/check_compose.py
python3 scripts/integration_test.py
python3 scripts/integration_test.py --ipv6
```

The Python integration suite requires the built `awg-panel:local` image and
Docker access. It uses a random Compose project name, temporary root-owned
secrets, a dedicated `172.30.189.0/24` bridge, and localhost ports `55182/udp` and
`18881/tcp`; these must be free. It starts real AWG clients in separate containers,
checks access control, API exports and persistence, removes only the test
container's firewall table to exercise repair, and deletes its containers,
network and data volume in a `finally` block. The IPv6 variant also verifies
internal IPv6 panel access and NAT66 to a simulated external endpoint. It never invokes `install.sh`,
changes host routes, or prunes unrelated Docker resources.

Real desktop/mobile import, upstream IPv6 Internet routing, SELinux enforcing
mode, production source cleanup and update workflows, and power-loss recovery
still require validation in their target environments. Unit tests verify atomic
reader behavior, but do not simulate a physical power failure.

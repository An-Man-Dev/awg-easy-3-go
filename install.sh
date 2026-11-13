#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export LC_ALL=C

REPO_URL="https://github.com/An-Man-Dev/awg-easy-3-go.git"
PROD_BRANCH="main"
INSTALL_DIR="/opt/awg-panel"
IMAGE="awg-panel:local"
DEV_MODE=false
UPDATE=false
CONFIG_FILE=""
BUILD_TMP=""
STAGED_WEB=""
OLD_WEB=""
SWAPPED=false
SUCCESS=false
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
START_SOURCE="$SOURCE_DIR"

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
usage() { say 'Usage: ./install.sh [--config /path/to/install.conf] [--update]'; }
while (($#)); do
  case "$1" in
    --config) (($# >= 2)) || die '--config needs a file'; CONFIG_FILE="$2"; shift 2 ;;
    --update) UPDATE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "Unknown option: $1" ;;
  esac
done
[[ $EUID == 0 ]] || die 'Run this installer as root.'
for command in docker git flock realpath mktemp cp mv sync od tr ip grep find date readlink sed; do command -v "$command" >/dev/null || die "Required command is missing: $command"; done
docker compose version >/dev/null || die 'Docker Compose v2 is required.'
docker info >/dev/null || die 'Docker daemon is unavailable.'
[[ -c /dev/net/tun ]] || die '/dev/net/tun is required.'
mkdir -p "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"
exec 9>"$INSTALL_DIR/.install.lock"
flock -n 9 || die 'Another installation is in progress.'

cleanup() {
  local status=$?
  if [[ "$SWAPPED" == true && "$SUCCESS" != true && -n "$OLD_WEB" ]]; then
    ln -s "$OLD_WEB" "$INSTALL_DIR/.web-rollback-$$"
    mv -Tf "$INSTALL_DIR/.web-rollback-$$" "$INSTALL_DIR/web"
    say 'Previous web release restored. State and keys have been retained.' >&2
  fi
  if [[ -n "$BUILD_TMP" && "$BUILD_TMP" == /tmp/awg-build-* && -d "$BUILD_TMP" ]]; then rm -rf -- "$BUILD_TMP"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

keys=(AWG_HOST AWG_PORT AWG_PANEL_PORT AWG_EXTERNAL_PANEL_BIND AWG_EXTERNAL_PANEL_PUBLISH AWG_PUBLIC_ORIGIN AWG_TRUSTED_PROXIES AWG_IPV6_MODE AWG_PASSWORD)
declare -A original=()
for key in "${keys[@]}"; do if [[ -v "$key" ]]; then original["$key"]="${!key}"; fi; done
load_config() {
  local file="$1" line key value
  [[ -f "$file" ]] || die "Configuration file not found: $file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == *=* ]] || die 'Configuration lines must use KEY=value.'
    key="${line%%=*}"; value="${line#*=}"
    case "$key" in AWG_HOST|AWG_PORT|AWG_PANEL_PORT|AWG_EXTERNAL_PANEL_BIND|AWG_EXTERNAL_PANEL_PUBLISH|AWG_PUBLIC_ORIGIN|AWG_TRUSTED_PROXIES|AWG_IPV6_MODE|AWG_PASSWORD) ;; *) die "Unknown configuration key: $key" ;; esac
    if [[ ${#value} -ge 2 ]]; then
      if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then value="${value:1:${#value}-2}"; fi
    fi
    printf -v "$key" '%s' "$value"
  done < "$file"
}
if [[ "$UPDATE" == true ]]; then
  load_config "$INSTALL_DIR/install.conf"
elif [[ -n "$CONFIG_FILE" ]]; then
  load_config "$CONFIG_FILE"
elif [[ -f "$SOURCE_DIR/install.conf" ]]; then
  load_config "$SOURCE_DIR/install.conf"
elif [[ -f "$SOURCE_DIR/.env" ]]; then
  load_config "$SOURCE_DIR/.env"
elif [[ -f "$INSTALL_DIR/install.conf" ]]; then
  load_config "$INSTALL_DIR/install.conf"
fi
for key in "${!original[@]}"; do printf -v "$key" '%s' "${original[$key]}"; done
prompt() {
  local key="$1" label="$2" fallback="$3" answer
  if [[ ! -v "$key" ]]; then
    if [[ -t 0 ]]; then read -r -p "$label${fallback:+ [$fallback]}: " answer; printf -v "$key" '%s' "${answer:-$fallback}"
    else printf -v "$key" '%s' "$fallback"; fi
  fi
}
prompt AWG_HOST 'Domain or Public IP' ''
prompt AWG_PORT 'VPN UDP Port' '51820'
prompt AWG_PANEL_PORT 'Admin Panel Port' '8881'
if [[ ! -v AWG_EXTERNAL_PANEL_BIND ]]; then
  answer=n
  if [[ -t 0 ]]; then read -r -p 'Enable external panel bind for Caddy/reverse-proxy? [y/N]: ' answer; fi
  case "$answer" in
    y|Y|yes|YES) AWG_EXTERNAL_PANEL_BIND="0.0.0.0:$AWG_PANEL_PORT"; prompt AWG_EXTERNAL_PANEL_PUBLISH 'Host bind address and port' "127.0.0.1:$AWG_PANEL_PORT"; prompt AWG_PUBLIC_ORIGIN 'Public HTTPS origin (optional)' '' ;;
    n|N|no|NO|'') AWG_EXTERNAL_PANEL_BIND='' ;;
    *) die 'Answer must be y or n.' ;;
  esac
fi
prompt AWG_IPV6_MODE 'IPv6 mode: auto / nat66 / disabled' 'auto'
: "${AWG_EXTERNAL_PANEL_PUBLISH:=127.0.0.1:$AWG_PANEL_PORT}"
: "${AWG_PUBLIC_ORIGIN:=}"
# The generated bridge has a fixed host gateway, suitable for a host Caddy process.
if [[ ! -v AWG_TRUSTED_PROXIES ]]; then AWG_TRUSTED_PROXIES=172.30.88.1/32; fi
if [[ -z "${AWG_PASSWORD:-}" ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p 'Admin Password (12+ characters; blank generates one): ' AWG_PASSWORD; printf '\n'
    if [[ -n "$AWG_PASSWORD" ]]; then read -r -s -p 'Confirm Admin Password: ' confirmation; printf '\n'; [[ "$AWG_PASSWORD" == "$confirmation" ]] || die 'Passwords do not match.'; fi
  fi
  if [[ -z "${AWG_PASSWORD:-}" ]]; then AWG_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"; printf 'Generated admin password: %s\n' "$AWG_PASSWORD"; fi
fi
[[ -n "$AWG_HOST" && "$AWG_HOST" =~ ^[A-Za-z0-9.:-]+$ ]] || die 'AWG_HOST must be a domain or IP without a scheme, path, or brackets.'
for key in AWG_PORT AWG_PANEL_PORT; do
  value="${!key}"; [[ "$value" =~ ^[0-9]{1,5}$ ]] && ((10#$value >= 1 && 10#$value <= 65535)) || die "$key must be between 1 and 65535."
  printf -v "$key" '%d' "$((10#$value))"
done
[[ ${#AWG_PASSWORD} -ge 12 && ${#AWG_PASSWORD} -le 256 ]] || die 'Admin password must contain 12 to 256 characters.'
for key in "${keys[@]}"; do value="${!key}"; [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$key must be a single line."; done
case "$AWG_IPV6_MODE" in auto|nat66|disabled) ;; *) die 'IPv6 mode must be auto, nat66, or disabled.' ;; esac
validate_bind() {
  local value="$1" host port octet
  local -a octets
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$ ]] || die 'Bind addresses must use IPv4:port.'
  host="${value%:*}"; port="${value##*:}"
  ((10#$port >= 1 && 10#$port <= 65535)) || die 'Invalid bind port.'
  IFS=. read -r -a octets <<< "$host"
  for octet in "${octets[@]}"; do
    ((10#$octet <= 255)) || die 'Invalid bind IPv4 address.'
    [[ "$octet" == 0 || "$octet" != 0* ]] || die 'IPv4 octets must not contain leading zeros.'
  done
}
if [[ -n "$AWG_EXTERNAL_PANEL_BIND" ]]; then
  validate_bind "$AWG_EXTERNAL_PANEL_BIND"; validate_bind "$AWG_EXTERNAL_PANEL_PUBLISH"
  case "${AWG_EXTERNAL_PANEL_BIND%:*}" in 0.0.0.0|172.30.88.2) ;; *) die 'The generated bridge requires an external container bind of 0.0.0.0 or 172.30.88.2.' ;; esac
fi
[[ -z "$AWG_PUBLIC_ORIGIN" || "$AWG_PUBLIC_ORIGIN" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || die 'Public origin must be an HTTPS origin without a trailing slash.'

if [[ "$UPDATE" == true ]]; then
  [[ "$REPO_URL" != *YOUR_USER* ]] || die 'Set REPO_URL in the installed script before using --update.'
  BUILD_TMP="$(mktemp -d /tmp/awg-build-XXXXXX)"
  git clone --depth 1 --branch "$PROD_BRANCH" --single-branch "$REPO_URL" "$BUILD_TMP/source"
  SOURCE_DIR="$BUILD_TMP/source"
else
  if git -C "$SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # symbolic-ref also works on a newly initialized dev branch with no commits.
    branch="$(git -C "$SOURCE_DIR" symbolic-ref --quiet --short HEAD 2>/dev/null || printf 'DETACHED')"
    if [[ "$branch" != "$PROD_BRANCH" ]]; then DEV_MODE=true; say 'Development branch detected, skipping source cleanup'; fi
  fi
fi
[[ -f "$SOURCE_DIR/go.mod" && -d "$SOURCE_DIR/web" && -f "$SOURCE_DIR/Dockerfile" ]] || die 'The source directory is incomplete.'

# Validate the destructive production path before making installation changes.
if [[ "$DEV_MODE" == false && "$UPDATE" == false ]]; then
  SOURCE_DIR="$(realpath -- "$SOURCE_DIR")"
  case "$SOURCE_DIR" in /|/home|/root|/tmp|/opt|/usr|/var|/etc|/opt/awg-panel|/opt/awg-panel/*) die 'Refusing source cleanup from a system or installation directory. Use a dedicated clone.' ;; esac
  [[ "$INSTALL_DIR/" != "$SOURCE_DIR/"* ]] || die 'The source directory contains the installation directory.'
  [[ "$SOURCE_DIR" != "${HOME:-/root}" ]] || die 'Refusing to remove the home directory.'
  say "Production installation will remove this source directory after success: $SOURCE_DIR"
fi

IPV6_ENABLED=false
if [[ "$AWG_IPV6_MODE" != disabled ]] && ip -6 route get 2606:4700:4700::1111 >/dev/null 2>&1 && ip -6 address show scope global | grep -q 'inet6 [23]'; then IPV6_ENABLED=true; fi
if [[ "$IPV6_ENABLED" == false && "$AWG_IPV6_MODE" != disabled ]]; then say 'No public IPv6 route detected. Installing in IPv4-only mode.'; fi
say 'Building native AWG and the panel in isolated Docker build stages...'
docker build --pull -t "$IMAGE" "$SOURCE_DIR"
image_size="$(docker image inspect "$IMAGE" --format '{{.Size}}')"
printf 'Runtime image size: %s bytes (target: less than 45 MiB).\n' "$image_size"

mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/releases"
chmod 700 "$INSTALL_DIR/data" "$INSTALL_DIR/releases"
release="web-$(date -u +%Y%m%dT%H%M%SZ)-$$"
STAGED_WEB="$INSTALL_DIR/releases/$release"
mkdir "$STAGED_WEB"
cp -a "$SOURCE_DIR/web/." "$STAGED_WEB/"
find "$STAGED_WEB" -type d -exec chmod 755 {} +
find "$STAGED_WEB" -type f -exec chmod 644 {} +
# Renaming a symlink atomically publishes a complete release. Containers are recreated below.
if [[ -L "$INSTALL_DIR/web" ]]; then
  OLD_WEB="$(readlink "$INSTALL_DIR/web")"
elif [[ -e "$INSTALL_DIR/web" ]]; then
  die 'Existing web path is not a managed symlink. Move it aside before installing.'
fi
ln -s "releases/$release" "$INSTALL_DIR/.web-next-$$"
mv -Tf "$INSTALL_DIR/.web-next-$$" "$INSTALL_DIR/web"
SWAPPED=true

config_tmp="$(mktemp "$INSTALL_DIR/.config-XXXXXX")"
for key in "${keys[@]}"; do printf '%s="%s"\n' "$key" "${!key}" >> "$config_tmp"; done
chmod 600 "$config_tmp"; sync -f "$config_tmp"; mv -f "$config_tmp" "$INSTALL_DIR/install.conf"
password_tmp="$(mktemp "$INSTALL_DIR/.password-XXXXXX")"
printf '%s' "$AWG_PASSWORD" > "$password_tmp"
chmod 600 "$password_tmp"; sync -f "$password_tmp"; mv -f "$password_tmp" "$INSTALL_DIR/admin-password"

yaml() { local v="${1//\'/\'\'}"; printf "'%s'" "$v"; }
compose_tmp="$(mktemp "$INSTALL_DIR/.compose-XXXXXX")"
{
  cat <<'YAML'
name: awg-panel
services:
  panel:
    image: awg-panel:local
    restart: unless-stopped
    read_only: true
    init: true
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    security_opt: [no-new-privileges:true]
    devices:
      - /dev/net/tun:/dev/net/tun
    tmpfs:
      - /run:rw,noexec,nosuid,size=8m,mode=755
      - /tmp:rw,noexec,nosuid,size=8m,mode=1777
    volumes:
      - /opt/awg-panel/data:/data:Z
      - /opt/awg-panel/web:/app/web:ro,z
      - /opt/awg-panel/admin-password:/run/secrets/admin-password:ro,Z
    environment:
      AWG_PASSWORD_FILE: /run/secrets/admin-password
YAML
  for key in AWG_HOST AWG_PORT AWG_PANEL_PORT AWG_EXTERNAL_PANEL_BIND AWG_PUBLIC_ORIGIN AWG_TRUSTED_PROXIES AWG_IPV6_MODE; do
    value="${!key}"
    if [[ "$key" == AWG_IPV6_MODE && "$IPV6_ENABLED" == false ]]; then value=disabled; fi
    printf '      %s: ' "$key"; yaml "$value"; printf '\n'
  done
  printf '    ports:\n      - "%s:%s/udp"\n' "$AWG_PORT" "$AWG_PORT"
  if [[ -n "$AWG_EXTERNAL_PANEL_BIND" ]]; then printf '      - "%s:%s/tcp"\n' "$AWG_EXTERNAL_PANEL_PUBLISH" "${AWG_EXTERNAL_PANEL_BIND##*:}"; fi
  cat <<'YAML'
    sysctls:
      net.ipv4.ip_forward: '1'
YAML
  if [[ "$IPV6_ENABLED" == true ]]; then printf "      net.ipv6.conf.all.forwarding: '1'\n      net.ipv6.conf.all.disable_ipv6: '0'\n"; fi
  cat <<'YAML'
    networks:
      vpn:
        ipv4_address: 172.30.88.2
    stop_grace_period: 20s
    pids_limit: 128
    logging:
      driver: json-file
      options:
        max-size: 5m
        max-file: '2'
networks:
  vpn:
    driver: bridge
YAML
  if [[ "$IPV6_ENABLED" == true ]]; then printf '    enable_ipv6: true\n'; fi
  cat <<'YAML'
    ipam:
      config:
        - subnet: 172.30.88.0/24
          gateway: 172.30.88.1
YAML
  if [[ "$IPV6_ENABLED" == true ]]; then printf '        - subnet: fd42:9::/64\n          gateway: fd42:9::1\n'; fi
} > "$compose_tmp"
chmod 600 "$compose_tmp"; sync -f "$compose_tmp"; mv -f "$compose_tmp" "$INSTALL_DIR/docker-compose.yml"
sync -f "$INSTALL_DIR"
cd "$INSTALL_DIR"
docker compose config --quiet
if existing_ipv6="$(docker network inspect awg-panel_vpn --format '{{.EnableIPv6}}' 2>/dev/null)"; then
  if [[ "$existing_ipv6" != "$IPV6_ENABLED" ]]; then
    say 'IPv6 bridge mode changed; recreating the managed network.'
    docker compose down --timeout 20
  fi
fi
docker compose up -d --force-recreate --wait --wait-timeout 90

if [[ "$DEV_MODE" == false ]]; then
  install_tmp="$(mktemp "$INSTALL_DIR/.installer-XXXXXX")"
  cp "$SOURCE_DIR/install.sh" "$install_tmp"
  # Retain a configured repository URL when upstream still ships the template URL.
  if [[ "$REPO_URL" != *YOUR_USER* ]]; then
    escaped_repo="${REPO_URL//&/\\&}"; escaped_repo="${escaped_repo//|/\\|}"
    sed -i "s|^REPO_URL=.*|REPO_URL=\"$escaped_repo\"|" "$install_tmp"
  fi
  chmod 700 "$install_tmp"; sync -f "$install_tmp"; mv -f "$install_tmp" "$INSTALL_DIR/install.sh"
fi
SUCCESS=true
docker image prune -f
docker builder prune -f
printf '\nInstallation complete.\nInternal panel: http://10.8.0.1:%s\n' "$AWG_PANEL_PORT"
if [[ "$IPV6_ENABLED" == true ]]; then printf 'Internal IPv6 panel: http://[fd42:8::1]:%s\n' "$AWG_PANEL_PORT"; fi
if [[ -n "$AWG_EXTERNAL_PANEL_BIND" ]]; then
  printf 'Host reverse-proxy upstream: %s\n' "$AWG_EXTERNAL_PANEL_PUBLISH"
  proxy_site="${AWG_PUBLIC_ORIGIN#https://}"; proxy_site="${proxy_site:-$AWG_HOST}"
  printf '\nCaddy configuration (set AWG_PUBLIC_ORIGIN to its HTTPS origin):\n%s {\n    reverse_proxy %s\n}\n' "$proxy_site" "$AWG_EXTERNAL_PANEL_PUBLISH"
fi
say 'Import the following home-device configuration before using the internal panel:'
docker compose exec -T panel ./awg-panel --bootstrap
if [[ "$DEV_MODE" == false && "$UPDATE" == false ]]; then
  [[ "$PWD" == "$INSTALL_DIR" && "$SOURCE_DIR" == "$START_SOURCE" ]] || die 'Source cleanup path changed unexpectedly.'
  rm -rf -- "$SOURCE_DIR"
  say 'Production source directory removed.'
fi
say 'Settings: /opt/awg-panel/install.conf'
say 'State and private keys: /opt/awg-panel/data/state.json'

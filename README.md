<p align="center"><img src="web/favicon.svg" width="96" height="96" alt="AWG Panel logo"></p>

# AWG Panel

**English** · [Русский](README.ru.md)

A lightweight, self-hosted web panel for **AmneziaWG 3**, written in Go with SQLite. Manage devices, user accounts and VPN settings from your browser.

- Separate administrator and user accounts, with optional two-factor authentication.
- Home devices share a network; guest devices get internet access only.
- Connection links, QR codes and configuration files, with optional client private-key storage.
- Encrypted configuration export and import for moving to another server.

**Alpha:** under active development. This release establishes the database baseline; future schema changes must preserve data through versioned migrations.

## Quick start

You need a Linux server with root access, **Docker Engine and Docker Compose v2**, Git and `/dev/net/tun`. The installer also uses standard Linux tools, including Bash and `ip`. Allow inbound **UDP 51820** in your server/provider firewall, or the VPN port you choose.

### 1. Install

```sh
git clone --branch main --single-branch https://github.com/An-Man-Dev/awg-easy-3-go.git /tmp/awg-panel-src
cd /tmp/awg-panel-src
sudo ./install.sh
cd /
```

Enter your server's public IP or VPN hostname. For a simple setup, keep the default ports and answer **No** to external panel access. Choose an administrator password, or leave it blank to generate one.

The installer builds the image and installs the application in `/opt/awg-panel`. Installation from `main` removes the temporary source checkout afterwards.

### 2. Connect your first device

On the server, display the initial home-device profile:

```sh
sudo docker compose -f /opt/awg-panel/docker-compose.yml exec -T panel ./awg-panel --bootstrap
```

Import the printed `vpn://` connection link into **AmneziaVPN**, or copy the configuration into a client that supports the server's AmneziaWG 3 parameters. Enable the tunnel. This output contains private keys; keep it private.

### 3. Open the panel

With the VPN connected, open **http://10.8.0.1:8881** and sign in as **`admin`** using the password chosen during installation.

If you generated a password, read it on the server:

```sh
sudo cat /opt/awg-panel/admin-password
```

Add devices in **My devices**, manage users in **Accounts**, and configure the server from the navigation menu. Enable two-factor authentication under **Two-factor**.

## Credits and license

Inspired by [alexsemenovru/awg-easy-3](https://github.com/alexsemenovru/awg-easy-3), itself based on [JohnnyVBut/awg-easy](https://github.com/JohnnyVBut/awg-easy). This is an independent Go implementation and a non-commercial hobby project, not affiliated with or endorsed by Amnezia.

Original project code: [MIT](LICENSE). Dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

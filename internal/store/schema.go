package store

// Schema 8 is the first alpha baseline. Future schema changes require explicit,
// versioned migrations that preserve existing data. Reject unsupported versions;
// never silently replace a database. Pre-alpha schemas are not supported.
const schemaVersion = 8
const applicationID = 0x41574750 // AWGP

const schema = `
CREATE TABLE metadata (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 initialized INTEGER NOT NULL CHECK (initialized IN (0, 1)),
 import_available INTEGER NOT NULL CHECK(import_available IN (0,1))
) STRICT;
INSERT INTO metadata VALUES (1, 0, 1);
CREATE TABLE accounts (
 id TEXT PRIMARY KEY NOT NULL,
 login TEXT NOT NULL UNIQUE CHECK (length(login) BETWEEN 1 AND 64),
 password_hash TEXT NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 role TEXT NOT NULL CHECK (role IN ('superadmin', 'admin', 'user')),
 enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
 manager_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT,
 created_at TEXT NOT NULL,
 CHECK ((role='user' AND manager_id IS NOT NULL AND manager_id<>id) OR (role IN ('admin','superadmin') AND manager_id IS NULL))
) STRICT;
CREATE INDEX accounts_manager ON accounts(manager_id);
CREATE TRIGGER account_manager_insert BEFORE INSERT ON accounts
 WHEN NEW.manager_id IS NOT NULL
 BEGIN
 SELECT RAISE(ABORT, 'manager must be an administrator') WHERE NOT EXISTS
 (SELECT 1 FROM accounts WHERE id = NEW.manager_id AND role = 'admin');
 END;
CREATE TRIGGER account_manager_update BEFORE UPDATE OF manager_id, role ON accounts
 BEGIN
 SELECT RAISE(ABORT, 'manager must be an administrator') WHERE NEW.manager_id IS NOT NULL AND NOT EXISTS
 (SELECT 1 FROM accounts WHERE id = NEW.manager_id AND role = 'admin');
 SELECT RAISE(ABORT, 'administrator still owns users') WHERE NEW.role <> 'admin' AND EXISTS
 (SELECT 1 FROM accounts WHERE manager_id = OLD.id);
 END;
CREATE TRIGGER protect_superadmin_delete BEFORE DELETE ON accounts
 WHEN OLD.role='superadmin' BEGIN SELECT RAISE(ABORT,'superadministrator cannot be deleted'); END;
CREATE TRIGGER protect_superadmin_update BEFORE UPDATE OF enabled,role ON accounts
 WHEN OLD.role='superadmin' AND (NEW.enabled=0 OR NEW.role<>'superadmin')
 BEGIN SELECT RAISE(ABORT,'superadministrator cannot be disabled or demoted'); END;
CREATE TABLE account_totp (
 account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 secret BLOB NOT NULL,
 last_step INTEGER NOT NULL CHECK(last_step>=0)
) STRICT;
CREATE TABLE recovery_codes (
 account_id TEXT NOT NULL REFERENCES account_totp(account_id) ON DELETE CASCADE,
 hash BLOB NOT NULL CHECK(length(hash)=32),
 PRIMARY KEY(account_id,hash)
) STRICT;
CREATE TABLE mfa_attempts (
 account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 window_start INTEGER NOT NULL,
 failures INTEGER NOT NULL CHECK(failures>=0)
) STRICT;
CREATE TABLE audit (
 id INTEGER PRIMARY KEY,
 at TEXT NOT NULL,
 actor TEXT NOT NULL,
 action TEXT NOT NULL,
 target TEXT NOT NULL
) STRICT;
CREATE TABLE server (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 private_key TEXT NOT NULL,
 public_key TEXT NOT NULL
) STRICT;
CREATE TABLE awg_profile (
 name TEXT PRIMARY KEY NOT NULL,
 value TEXT NOT NULL
) STRICT;
CREATE TABLE devices (
 id TEXT PRIMARY KEY NOT NULL,
 owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
 name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
 network_group TEXT NOT NULL CHECK (network_group IN ('home', 'guest')),
 slot INTEGER NOT NULL UNIQUE CHECK (slot BETWEEN 2 AND 254),
 enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
 public_key TEXT NOT NULL UNIQUE,
 preshared_key TEXT NOT NULL,
 created_at TEXT NOT NULL
) STRICT;
CREATE INDEX devices_owner ON devices(owner_id);
CREATE TABLE key_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 revision INTEGER NOT NULL CHECK(revision>0),
 retain INTEGER NOT NULL CHECK(retain IN (0,1))
) STRICT;
CREATE TABLE device_secrets (
 device_id TEXT PRIMARY KEY NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 private_key TEXT NOT NULL CHECK (length(private_key) = 44)
) STRICT;
CREATE TABLE device_observations (
 device_id TEXT PRIMARY KEY NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 last_handshake INTEGER NOT NULL CHECK (last_handshake > 0)
) STRICT;
CREATE TRIGGER rotated_device_observation AFTER UPDATE OF public_key ON devices
 WHEN OLD.public_key <> NEW.public_key BEGIN
 DELETE FROM device_observations WHERE device_id=NEW.id;
 END;
CREATE TRIGGER enforce_key_retention BEFORE INSERT ON device_secrets
 WHEN (SELECT retain FROM key_policy WHERE id=1)=0 AND NOT EXISTS
 (SELECT 1 FROM device_secrets WHERE device_id=NEW.device_id AND private_key=NEW.private_key)
 BEGIN SELECT RAISE(ABORT,'client key retention is disabled'); END;
CREATE TRIGGER enforce_key_retention_update BEFORE UPDATE OF private_key ON device_secrets
 WHEN (SELECT retain FROM key_policy WHERE id=1)=0 AND OLD.private_key<>NEW.private_key
 BEGIN SELECT RAISE(ABORT,'client key retention is disabled'); END;
CREATE TABLE server_addresses (
 id INTEGER PRIMARY KEY CHECK(id=1),
 revision INTEGER NOT NULL CHECK(revision>0),
 vpn_host TEXT NOT NULL,
 panel_origin TEXT NOT NULL
) STRICT;
CREATE TABLE app_settings (
 id INTEGER PRIMARY KEY CHECK (id=1),
 revision INTEGER NOT NULL CHECK (revision>0),
 server_name TEXT NOT NULL,
 dns TEXT NOT NULL CHECK (json_valid(dns) AND json_type(dns)='array'),
 mtu INTEGER NOT NULL CHECK (mtu BETWEEN 1280 AND 9000),
 keepalive INTEGER NOT NULL CHECK (keepalive BETWEEN 0 AND 65535),
 allowed_ips TEXT NOT NULL CHECK (json_valid(allowed_ips) AND json_type(allowed_ips)='array')
) STRICT;
CREATE TRIGGER used_account_installation AFTER INSERT ON accounts WHEN (SELECT initialized FROM metadata WHERE id=1)=1
 BEGIN UPDATE metadata SET import_available=0 WHERE id=1; END;
CREATE TRIGGER used_device_installation_insert AFTER INSERT ON devices WHEN (SELECT initialized FROM metadata WHERE id=1)=1
 BEGIN UPDATE metadata SET import_available=0 WHERE id=1; END;
CREATE TRIGGER used_device_installation_update AFTER UPDATE ON devices WHEN (SELECT initialized FROM metadata WHERE id=1)=1
 BEGIN UPDATE metadata SET import_available=0 WHERE id=1; END;
CREATE TRIGGER used_device_installation_delete AFTER DELETE ON devices WHEN (SELECT initialized FROM metadata WHERE id=1)=1
 BEGIN UPDATE metadata SET import_available=0 WHERE id=1; END;
`

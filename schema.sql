PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tags (
    uid TEXT PRIMARY KEY,
    member_key TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    last_counter INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    note TEXT,
    enrolled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    member_key TEXT PRIMARY KEY,
    display_name TEXT,
    active_until TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'authentik'
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK(role IN ('gate','writer','both')),
    offline_verify INTEGER NOT NULL DEFAULT 0,
    presence TEXT NOT NULL DEFAULT 'offline',
    last_seen TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    device_id TEXT,
    uid TEXT,
    counter INTEGER,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_key TEXT,
    uid TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('ban','allow')),
    expires_at TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    CHECK (member_key IS NOT NULL OR uid IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS sync_state (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    last_success TEXT,
    last_attempt TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    uid TEXT NOT NULL,
    member_key TEXT NOT NULL,
    device_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

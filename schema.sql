PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tags (
    uid TEXT PRIMARY KEY,
    member_key TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    last_counter INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    note TEXT,
    enrolled_at TEXT NOT NULL,
    entry_gen INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS members (
    member_key TEXT PRIMARY KEY,
    display_name TEXT,
    phone TEXT,
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
    reason TEXT NOT NULL,
    member_key TEXT
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

CREATE TABLE IF NOT EXISTS tap_reports (
    tap_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    uid TEXT NOT NULL,
    counter INTEGER NOT NULL,
    decision TEXT,
    reason TEXT,
    time_uncertain INTEGER NOT NULL DEFAULT 0,
    dev_ts TEXT,
    recv_ts TEXT NOT NULL,
    key_version INTEGER,
    kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    device_id TEXT,
    uid TEXT,
    kind TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS roster_events (
    roster_gen INTEGER NOT NULL,
    uid TEXT NOT NULL,
    entry_blob TEXT NOT NULL,
    ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_roster_events_roster_gen ON roster_events(roster_gen);

-- One ACTIVE tag per member: a valid key for an identity is singular, like
-- a password. Enrollment is REPLACEMENT — provisioning a new tag revokes
-- the member's other tags (lost-card flow: enroll the replacement through
-- the supervised provisioning flow, then the lost plastic is inert). A
-- revoked tag is revivable only by re-provisioning it, which re-keys it.
--
-- Migration (idempotent): before the index exists (or if it was somehow
-- evaded), retire every active tag except the member's newest-enrolled one.
UPDATE tags SET status = 'revoked'
WHERE status = 'active' AND rowid NOT IN (
    SELECT MAX(rowid) FROM tags WHERE status = 'active' GROUP BY member_key
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tags_one_active_per_member
    ON tags(member_key) WHERE status = 'active';

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- schema_meta — single source of truth for non-versioned project metadata
-- (mode the DB was bootstrapped in, install id, etc.). Distinct from goose's
-- own `goose_db_version` so the audit log can reference it without coupling
-- to migration tooling internals.
-- ---------------------------------------------------------------------------
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- kv — small typed key/value table used for first-boot bootstraps (admin
-- password seed, master-secret fingerprint, last backup pointer). Stays small
-- by design; large state goes in its own table.
-- ---------------------------------------------------------------------------
CREATE TABLE kv (
    key        TEXT PRIMARY KEY,
    value      BYTEA       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- captured_mail — mail capture queue used when SK_MODE=eval. Persisted so an
-- evaluator can restart the container without losing the captured artefacts.
-- ---------------------------------------------------------------------------
CREATE TABLE captured_mail (
    id          BIGSERIAL    PRIMARY KEY,
    to_addr     TEXT         NOT NULL,
    subject     TEXT         NOT NULL,
    body        TEXT         NOT NULL,
    captured_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX captured_mail_captured_at_idx ON captured_mail (captured_at DESC);

-- ---------------------------------------------------------------------------
-- audit_log — hash-chained, append-only event log (FR-E.*). Forward-only;
-- never UPDATE or DELETE in production. entry_hash = sha256(prev_hash ||
-- canonical(event_type || actor || target || details_json || sequence_no)).
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    sequence_no   BIGSERIAL    PRIMARY KEY,
    occurred_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    event_type    TEXT         NOT NULL,
    actor         TEXT,
    target        TEXT,
    details_json  TEXT         NOT NULL DEFAULT '{}',
    prev_hash     TEXT         NOT NULL DEFAULT '',
    entry_hash    TEXT         NOT NULL
);

CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at);
CREATE INDEX audit_log_event_type_idx  ON audit_log (event_type);

INSERT INTO schema_meta (key, value) VALUES
    ('installed_at', NOW()::text),
    ('schema_dialect', 'postgres');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS captured_mail;
DROP TABLE IF EXISTS kv;
DROP TABLE IF EXISTS schema_meta;
-- +goose StatementEnd

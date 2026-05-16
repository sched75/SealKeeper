-- +goose Up
-- +goose StatementBegin

-- See migrations/postgres/0001_initial_schema.sql for the canonical comments.
-- SQLite ships in eval mode; Postgres is the production target. The two
-- schemas stay in lockstep on column names and semantics — only types and
-- default expressions differ.

CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE kv (
    key        TEXT PRIMARY KEY,
    value      BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE captured_mail (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    to_addr     TEXT    NOT NULL,
    subject     TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    captured_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX captured_mail_captured_at_idx ON captured_mail (captured_at DESC);

CREATE TABLE audit_log (
    sequence_no   INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type    TEXT    NOT NULL,
    actor         TEXT,
    target        TEXT,
    details_json  TEXT    NOT NULL DEFAULT '{}',
    prev_hash     TEXT    NOT NULL DEFAULT '',
    entry_hash    TEXT    NOT NULL
);

CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at);
CREATE INDEX audit_log_event_type_idx  ON audit_log (event_type);

INSERT INTO schema_meta (key, value) VALUES
    ('installed_at',   CURRENT_TIMESTAMP),
    ('schema_dialect', 'sqlite');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS captured_mail;
DROP TABLE IF EXISTS kv;
DROP TABLE IF EXISTS schema_meta;
-- +goose StatementEnd

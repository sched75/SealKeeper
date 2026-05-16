-- +goose Up
-- +goose StatementBegin

CREATE TABLE request_tokens (
    token             TEXT PRIMARY KEY,
    email             TEXT NOT NULL,
    domain            TEXT NOT NULL,
    requested_ip_hash TEXT,
    requested_ua_hash TEXT,
    issued_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at        TEXT NOT NULL,
    consumed_at       TEXT,
    consumed_ip_hash  TEXT,
    consumed_ua_hash  TEXT
);

CREATE INDEX request_tokens_email_idx      ON request_tokens (email);
CREATE INDEX request_tokens_expires_at_idx ON request_tokens (expires_at);
-- Partial indexes are supported by SQLite 3.8+.
CREATE INDEX request_tokens_unconsumed_idx ON request_tokens (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE user_sessions (
    token              TEXT PRIMARY KEY,
    request_token      TEXT NOT NULL REFERENCES request_tokens (token) ON DELETE CASCADE,
    issued_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at         TEXT NOT NULL,
    idle_expires_at    TEXT NOT NULL,
    revoked_at         TEXT
);

CREATE INDEX user_sessions_expires_at_idx ON user_sessions (expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS request_tokens;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

CREATE TABLE admins (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    email                   TEXT    NOT NULL UNIQUE,
    password_hash           TEXT    NOT NULL,
    totp_secret_enc         BLOB,
    totp_recovery_codes_enc BLOB,
    force_password_change   INTEGER NOT NULL DEFAULT 0,
    force_totp_enroll       INTEGER NOT NULL DEFAULT 0,
    failed_attempts         INTEGER NOT NULL DEFAULT 0,
    locked_until            TEXT,
    disabled_at             TEXT,
    last_login_at           TEXT,
    created_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX admins_active_idx ON admins (email) WHERE disabled_at IS NULL;

CREATE TABLE admin_sessions (
    token            TEXT    PRIMARY KEY,
    admin_id         INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    issued_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at       TEXT    NOT NULL,
    idle_expires_at  TEXT    NOT NULL,
    csrf_token       TEXT    NOT NULL,
    ip_hash          TEXT,
    ua_hash          TEXT,
    revoked_at       TEXT
);

CREATE INDEX admin_sessions_admin_id_idx   ON admin_sessions (admin_id);
CREATE INDEX admin_sessions_expires_at_idx ON admin_sessions (expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS admins;
-- +goose StatementEnd

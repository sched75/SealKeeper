-- +goose Up
-- +goose StatementBegin

CREATE TABLE admin_webauthn_credentials (
    credential_id      TEXT    PRIMARY KEY,
    admin_id           INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    public_key         BLOB    NOT NULL,
    attestation_type   TEXT    NOT NULL DEFAULT 'none',
    transports         TEXT    NOT NULL DEFAULT '[]',
    aaguid             BLOB,
    sign_count         INTEGER NOT NULL DEFAULT 0,
    friendly_name      TEXT    NOT NULL DEFAULT '',
    user_verified      INTEGER NOT NULL DEFAULT 0,
    backup_eligible    INTEGER NOT NULL DEFAULT 0,
    backup_state       INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at       TEXT
);

CREATE INDEX admin_webauthn_credentials_admin_id_idx ON admin_webauthn_credentials (admin_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_webauthn_credentials;
-- +goose StatementEnd

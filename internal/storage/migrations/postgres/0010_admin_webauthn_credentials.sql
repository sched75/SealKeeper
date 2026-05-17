-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- admin_webauthn_credentials — passkeys / security keys bound to admins.
-- PRD: FR-C.19..23 (WebAuthn second factor, optional substitution for TOTP).
--
-- credential_id is the authenticator's opaque ID, stored as base64url so the
-- HTTP layer can pass it around without re-encoding. public_key is the COSE
-- key serialised by go-webauthn (CBOR), kept raw bytes.
-- ---------------------------------------------------------------------------
CREATE TABLE admin_webauthn_credentials (
    credential_id      TEXT         PRIMARY KEY,                 -- base64url(rawId)
    admin_id           BIGINT       NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    public_key         BYTEA        NOT NULL,                    -- COSE / CBOR
    attestation_type   TEXT         NOT NULL DEFAULT 'none',
    transports         TEXT         NOT NULL DEFAULT '[]',       -- JSON array of strings
    aaguid             BYTEA,
    sign_count         BIGINT       NOT NULL DEFAULT 0,
    friendly_name      TEXT         NOT NULL DEFAULT '',
    user_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
    backup_eligible    BOOLEAN      NOT NULL DEFAULT FALSE,
    backup_state       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at       TIMESTAMPTZ
);

CREATE INDEX admin_webauthn_credentials_admin_id_idx ON admin_webauthn_credentials (admin_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_webauthn_credentials;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- admins — administrator accounts.
-- PRD: FR-C.1..18.
-- ---------------------------------------------------------------------------
CREATE TABLE admins (
    id                      BIGSERIAL    PRIMARY KEY,
    email                   TEXT         NOT NULL UNIQUE,
    password_hash           TEXT         NOT NULL,                  -- bcrypt
    totp_secret_enc         BYTEA,                                  -- AES-256-GCM, NULL until enrolled
    totp_recovery_codes_enc BYTEA,                                  -- AES-256-GCM JSON array, used codes are zeroed in place
    force_password_change   BOOLEAN      NOT NULL DEFAULT FALSE,
    force_totp_enroll       BOOLEAN      NOT NULL DEFAULT FALSE,
    failed_attempts         INTEGER      NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    disabled_at             TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX admins_active_idx ON admins (email) WHERE disabled_at IS NULL;

-- ---------------------------------------------------------------------------
-- admin_sessions — short-lived cookie-bound sessions issued after a
-- successful login + TOTP. Absolute TTL 8h, idle TTL 30min (FR-C.6, FR-C.7).
-- ---------------------------------------------------------------------------
CREATE TABLE admin_sessions (
    token            TEXT         PRIMARY KEY,                 -- opaque 256-bit, base64url
    admin_id         BIGINT       NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    issued_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ  NOT NULL,                    -- absolute hard cap
    idle_expires_at  TIMESTAMPTZ  NOT NULL,                    -- bumped on each touch
    csrf_token       TEXT         NOT NULL,                    -- double-submit cookie token
    ip_hash          TEXT,
    ua_hash          TEXT,
    revoked_at       TIMESTAMPTZ
);

CREATE INDEX admin_sessions_admin_id_idx   ON admin_sessions (admin_id);
CREATE INDEX admin_sessions_expires_at_idx ON admin_sessions (expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS admins;
-- +goose StatementEnd

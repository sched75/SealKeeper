-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- request_tokens — opaque single-use bearer tokens minted on POST
-- /api/v1/request. The reveal page receives one in its URL path; consuming
-- it (GET /api/v1/policy?token=...) creates a user_session and flips
-- consumed_at. PRD: FR-B.18, FR-B.36..38.
-- ---------------------------------------------------------------------------
CREATE TABLE request_tokens (
    token             TEXT         PRIMARY KEY,
    email             TEXT         NOT NULL,
    domain            TEXT         NOT NULL,
    requested_ip_hash TEXT,
    requested_ua_hash TEXT,
    issued_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ  NOT NULL,
    consumed_at       TIMESTAMPTZ,
    consumed_ip_hash  TEXT,
    consumed_ua_hash  TEXT
);

CREATE INDEX request_tokens_email_idx       ON request_tokens (email);
CREATE INDEX request_tokens_expires_at_idx  ON request_tokens (expires_at);
CREATE INDEX request_tokens_unconsumed_idx  ON request_tokens (expires_at) WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- user_sessions — created when the reveal page consumes its token. Carries
-- the short window during which the JS may re-fetch the policy or call
-- regenerate. FR-D.* session TTL defaults to 15 min, idle 5 min.
-- ---------------------------------------------------------------------------
CREATE TABLE user_sessions (
    token              TEXT         PRIMARY KEY,
    request_token      TEXT         NOT NULL REFERENCES request_tokens (token) ON DELETE CASCADE,
    issued_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ  NOT NULL,
    idle_expires_at    TIMESTAMPTZ  NOT NULL,
    revoked_at         TIMESTAMPTZ
);

CREATE INDEX user_sessions_expires_at_idx ON user_sessions (expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS request_tokens;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- domains — allowlist of email domains that may request reveal tokens.
-- PRD: FR-C.20..26.
--
-- name stores either an exact FQDN ("entreprise.com") or a wildcard
-- subdomain prefix ("*.entreprise.com"). The matcher in internal/domains
-- handles the difference; the SQL just guarantees uniqueness on the raw
-- canonical form (lowercased).
-- ---------------------------------------------------------------------------
CREATE TABLE domains (
    id                  BIGSERIAL    PRIMARY KEY,
    name                TEXT         NOT NULL UNIQUE,
    description         TEXT         NOT NULL DEFAULT '',
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by_admin_id BIGINT       REFERENCES admins(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX domains_active_idx ON domains (active) WHERE active = TRUE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS domains;
-- +goose StatementEnd

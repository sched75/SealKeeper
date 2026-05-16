-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- policies — per-domain, per-ANSSI-level generation policy.
-- PRD: FR-C.27..37.
--
-- UNIQUE(domain_id, anssi_level) enforces the FR-C.27 cap of one policy per
-- (domain, level): a domain may have at most three rows here (B1, B2, B3).
-- params_json carries the rest of the PolicyDescriptor shape from module A
-- (libraryId, numberOfWords, separatorOptions, …) as opaque JSON.
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    id                    BIGSERIAL    PRIMARY KEY,
    domain_id             BIGINT       NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    anssi_level           TEXT         NOT NULL CHECK (anssi_level IN ('B1','B2','B3')),
    name                  TEXT         NOT NULL,
    generator             TEXT         NOT NULL CHECK (generator IN ('G1','G2','G3')),
    params_json           TEXT         NOT NULL DEFAULT '{}',
    proposal_count        INTEGER      NOT NULL DEFAULT 5,
    regenerate_limit      INTEGER      NOT NULL DEFAULT 3,
    session_ttl_seconds   INTEGER      NOT NULL DEFAULT 900,
    notify_on_consult     BOOLEAN      NOT NULL DEFAULT FALSE,
    active                BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by_admin_id   BIGINT       REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, anssi_level)
);

CREATE INDEX policies_domain_active_idx ON policies (domain_id) WHERE active = TRUE;

-- ---------------------------------------------------------------------------
-- elevations — per-domain list of elevated emails.
-- PRD: FR-C.38..46. UNIQUE(domain_id, email) realises FR-C.39 (one email is
-- in at most one elevation list).
-- ---------------------------------------------------------------------------
CREATE TABLE elevations (
    id                    BIGSERIAL    PRIMARY KEY,
    domain_id             BIGINT       NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    email                 TEXT         NOT NULL,
    level                 TEXT         NOT NULL CHECK (level IN ('B2','B3')),
    reason                TEXT         NOT NULL DEFAULT '',
    created_by_admin_id   BIGINT       REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at          TIMESTAMPTZ,
    UNIQUE (domain_id, email)
);

CREATE INDEX elevations_lookup_idx ON elevations (email);
CREATE INDEX elevations_domain_idx ON elevations (domain_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS elevations;
DROP TABLE IF EXISTS policies;
-- +goose StatementEnd

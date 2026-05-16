-- +goose Up
-- +goose StatementBegin

CREATE TABLE policies (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id             INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    anssi_level           TEXT    NOT NULL CHECK (anssi_level IN ('B1','B2','B3')),
    name                  TEXT    NOT NULL,
    generator             TEXT    NOT NULL CHECK (generator IN ('G1','G2','G3')),
    params_json           TEXT    NOT NULL DEFAULT '{}',
    proposal_count        INTEGER NOT NULL DEFAULT 5,
    regenerate_limit      INTEGER NOT NULL DEFAULT 3,
    session_ttl_seconds   INTEGER NOT NULL DEFAULT 900,
    notify_on_consult     INTEGER NOT NULL DEFAULT 0,
    active                INTEGER NOT NULL DEFAULT 1,
    created_by_admin_id   INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (domain_id, anssi_level)
);

CREATE INDEX policies_domain_active_idx ON policies (domain_id) WHERE active = 1;

CREATE TABLE elevations (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id             INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    email                 TEXT    NOT NULL,
    level                 TEXT    NOT NULL CHECK (level IN ('B2','B3')),
    reason                TEXT    NOT NULL DEFAULT '',
    created_by_admin_id   INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at          TEXT,
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

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- branding — instance-wide identity (name + colours + logo).
-- PRD: FR-C.64..68.
--
-- The table is single-row by convention. internal/branding.Repo.Get
-- auto-creates id=1 on first read with sensible defaults so the public
-- surface always renders something.
--
-- Colours are stored as hex strings (#RRGGBB); validation lives in the
-- application layer because SQLite's CHECK constraints can't enforce the
-- regex portably across both dialects.
--
-- The logo is kept inline as a BYTEA blob (capped at 256 KB by FR-C.65),
-- avoiding the filesystem coordination required for content-addressable
-- storage on a single small asset.
-- ---------------------------------------------------------------------------
CREATE TABLE branding (
    id                    INTEGER     PRIMARY KEY,
    instance_name         TEXT        NOT NULL DEFAULT 'SealKeeper',
    primary_color         TEXT        NOT NULL DEFAULT '#1D4ED8',
    secondary_color       TEXT        NOT NULL DEFAULT '#F59E0B',
    tertiary_color        TEXT        NOT NULL DEFAULT '#0F172A',
    contact_url           TEXT        NOT NULL DEFAULT '',
    logo_bytes            BYTEA,
    logo_mime             TEXT,
    updated_by_admin_id   BIGINT      REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (id = 1)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS branding;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

CREATE TABLE branding (
    id                    INTEGER PRIMARY KEY,
    instance_name         TEXT    NOT NULL DEFAULT 'SealKeeper',
    primary_color         TEXT    NOT NULL DEFAULT '#1D4ED8',
    secondary_color       TEXT    NOT NULL DEFAULT '#F59E0B',
    tertiary_color        TEXT    NOT NULL DEFAULT '#0F172A',
    contact_url           TEXT    NOT NULL DEFAULT '',
    logo_bytes            BLOB,
    logo_mime             TEXT,
    updated_by_admin_id   INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (id = 1)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS branding;
-- +goose StatementEnd

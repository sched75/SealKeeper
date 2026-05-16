-- +goose Up
-- +goose StatementBegin

CREATE TABLE domains (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL UNIQUE,
    description         TEXT    NOT NULL DEFAULT '',
    active              INTEGER NOT NULL DEFAULT 1,
    created_by_admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX domains_active_idx ON domains (active) WHERE active = 1;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS domains;
-- +goose StatementEnd

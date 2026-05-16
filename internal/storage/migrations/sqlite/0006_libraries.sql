-- +goose Up
-- +goose StatementBegin

CREATE TABLE libraries (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT    NOT NULL,
    kind                  TEXT    NOT NULL CHECK (kind IN ('dictionary','corpus')),
    language              TEXT    NOT NULL,
    description           TEXT    NOT NULL DEFAULT '',
    sha256                TEXT    NOT NULL UNIQUE,
    entry_count           INTEGER NOT NULL,
    size_bytes            INTEGER NOT NULL,
    file_path             TEXT    NOT NULL,
    system_flag           INTEGER NOT NULL DEFAULT 0,
    created_by_admin_id   INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX libraries_kind_lang_idx ON libraries (kind, language);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS libraries;
-- +goose StatementEnd

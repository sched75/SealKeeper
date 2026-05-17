-- +goose Up
-- +goose StatementBegin

CREATE TABLE smtp_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    host                TEXT    NOT NULL DEFAULT '',
    port                INTEGER NOT NULL DEFAULT 587,
    username            TEXT    NOT NULL DEFAULT '',
    password_enc        BLOB,
    from_addr           TEXT    NOT NULL DEFAULT '',
    tls_mode            TEXT    NOT NULL DEFAULT 'auto',
    server_name         TEXT    NOT NULL DEFAULT '',
    insecure_tls        INTEGER NOT NULL DEFAULT 0,
    timeout_seconds     INTEGER NOT NULL DEFAULT 30,
    updated_by_admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS smtp_config;
-- +goose StatementEnd

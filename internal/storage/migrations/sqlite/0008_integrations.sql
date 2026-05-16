-- +goose Up
-- +goose StatementBegin

CREATE TABLE integrations (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT    NOT NULL UNIQUE,
    kind                  TEXT    NOT NULL CHECK (kind IN ('webhook','splunk','sentinel','elastic','syslog')),
    enabled               INTEGER NOT NULL DEFAULT 1,
    config_json           TEXT    NOT NULL DEFAULT '{}',
    filters_json          TEXT    NOT NULL DEFAULT '{}',
    created_by_admin_id   INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX integrations_enabled_idx ON integrations (enabled) WHERE enabled = 1;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS integrations;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

CREATE TABLE email_templates (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    kind                  TEXT    NOT NULL CHECK (kind IN ('reveal_link','post_consultation')),
    language              TEXT    NOT NULL,
    subject               TEXT    NOT NULL,
    text_body             TEXT    NOT NULL,
    html_body             TEXT    NOT NULL,
    updated_by_admin_id   INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (kind, language)
);

CREATE INDEX email_templates_kind_idx ON email_templates (kind);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS email_templates;
-- +goose StatementEnd

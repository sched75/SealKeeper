-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- email_templates — admin-editable mail bodies.
-- PRD: FR-C.69..75.
--
-- The package internal/mailtemplates ships system defaults that cover the
-- KindRevealLink template in FR + EN. This table carries OVERRIDES only: a
-- missing row means "use the built-in default for that (kind, language)".
-- That keeps the eval-mode 5-second pitch zero-config — the admin uploads
-- a custom template the moment it actually wants different copy.
--
-- subject / text / html are raw template sources (text/template + html/
-- template). The validator in the repo parses them on Upsert so a syntax
-- error never reaches the request pipeline.
-- ---------------------------------------------------------------------------
CREATE TABLE email_templates (
    id                    BIGSERIAL    PRIMARY KEY,
    kind                  TEXT         NOT NULL CHECK (kind IN ('reveal_link','post_consultation')),
    language              TEXT         NOT NULL,
    subject               TEXT         NOT NULL,
    text_body             TEXT         NOT NULL,
    html_body             TEXT         NOT NULL,
    updated_by_admin_id   BIGINT       REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (kind, language)
);

CREATE INDEX email_templates_kind_idx ON email_templates (kind);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS email_templates;
-- +goose StatementEnd

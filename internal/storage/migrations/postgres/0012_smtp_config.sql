-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- smtp_config — single-row relay configuration editable from /admin/smtp.
--
-- The password lands here AES-256-GCM-wrapped via cryptobox using
-- AAD sha256("sealkeeper-smtp"). An empty host means "no DB override —
-- fall back to the env-var configuration the binary booted with".
-- ---------------------------------------------------------------------------
CREATE TABLE smtp_config (
    id                  INTEGER     PRIMARY KEY CHECK (id = 1),
    host                TEXT        NOT NULL DEFAULT '',
    port                INTEGER     NOT NULL DEFAULT 587,
    username            TEXT        NOT NULL DEFAULT '',
    password_enc        BYTEA,
    from_addr           TEXT        NOT NULL DEFAULT '',
    tls_mode            TEXT        NOT NULL DEFAULT 'auto',
    server_name         TEXT        NOT NULL DEFAULT '',
    insecure_tls        BOOLEAN     NOT NULL DEFAULT FALSE,
    timeout_seconds     INTEGER     NOT NULL DEFAULT 30,
    updated_by_admin_id BIGINT      REFERENCES admins(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS smtp_config;
-- +goose StatementEnd

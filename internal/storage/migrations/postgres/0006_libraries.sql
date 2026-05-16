-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- libraries — uploaded dictionaries (G2 word lists) and corpora (G1
-- citation banks). PRD: FR-C.47..56.
--
-- sha256 is UNIQUE so re-uploading identical content is idempotent: the
-- second admin gets ErrAlreadyExists instead of a silent dedup duplicate.
-- file_path is relative to the libraries directory (SK_LIBRARIES_DIR),
-- typically `<sha256>.txt` for content-addressable storage.
-- system_flag marks libraries shipped with the binary — they cannot be
-- deleted from the admin UI (FR-C.52).
-- ---------------------------------------------------------------------------
CREATE TABLE libraries (
    id                    BIGSERIAL    PRIMARY KEY,
    name                  TEXT         NOT NULL,
    kind                  TEXT         NOT NULL CHECK (kind IN ('dictionary','corpus')),
    language              TEXT         NOT NULL,
    description           TEXT         NOT NULL DEFAULT '',
    sha256                TEXT         NOT NULL UNIQUE,
    entry_count           INTEGER      NOT NULL,
    size_bytes            BIGINT       NOT NULL,
    file_path             TEXT         NOT NULL,
    system_flag           BOOLEAN      NOT NULL DEFAULT FALSE,
    created_by_admin_id   BIGINT       REFERENCES admins(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX libraries_kind_lang_idx ON libraries (kind, language);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS libraries;
-- +goose StatementEnd

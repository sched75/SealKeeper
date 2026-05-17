-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Mirror of postgres/0011: re-paint a factory-defaulted branding row.
-- SQLite cannot ALTER a column DEFAULT, so we only run the UPDATE. The
-- bootstrap INSERT in internal/branding/branding.go passes explicit
-- values, which covers the new-install case for SQLite users.
-- ---------------------------------------------------------------------------

UPDATE branding
SET    primary_color   = '#7A1F2B',
       secondary_color = '#C9A961',
       tertiary_color  = '#1A1814',
       updated_at      = CURRENT_TIMESTAMP
WHERE  id = 1
  AND  primary_color   = '#1D4ED8'
  AND  secondary_color = '#F59E0B'
  AND  tertiary_color  = '#0F172A';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

UPDATE branding
SET    primary_color   = '#1D4ED8',
       secondary_color = '#F59E0B',
       tertiary_color  = '#0F172A',
       updated_at      = CURRENT_TIMESTAMP
WHERE  id = 1
  AND  primary_color   = '#7A1F2B'
  AND  secondary_color = '#C9A961'
  AND  tertiary_color  = '#1A1814';

-- +goose StatementEnd

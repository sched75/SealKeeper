-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- 0011_branding_heraldic_defaults
--
-- Migrates any branding row that still carries the v0.1 factory blue
-- defaults onto the heraldic palette used by /design. Rows that an
-- admin has touched (their colours no longer match the factory triple)
-- are left intact — the WHERE clause is conservative on purpose.
--
-- Column DEFAULTs are also updated so that a future bootstrap INSERT
-- that lands here without explicit values picks up the new palette
-- too. (Postgres-only — SQLite forbids ALTER COLUMN ... SET DEFAULT.)
-- ---------------------------------------------------------------------------

UPDATE branding
SET    primary_color   = '#7A1F2B',
       secondary_color = '#C9A961',
       tertiary_color  = '#1A1814',
       updated_at      = NOW()
WHERE  id = 1
  AND  primary_color   = '#1D4ED8'
  AND  secondary_color = '#F59E0B'
  AND  tertiary_color  = '#0F172A';

ALTER TABLE branding ALTER COLUMN primary_color   SET DEFAULT '#7A1F2B';
ALTER TABLE branding ALTER COLUMN secondary_color SET DEFAULT '#C9A961';
ALTER TABLE branding ALTER COLUMN tertiary_color  SET DEFAULT '#1A1814';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE branding ALTER COLUMN primary_color   SET DEFAULT '#1D4ED8';
ALTER TABLE branding ALTER COLUMN secondary_color SET DEFAULT '#F59E0B';
ALTER TABLE branding ALTER COLUMN tertiary_color  SET DEFAULT '#0F172A';

UPDATE branding
SET    primary_color   = '#1D4ED8',
       secondary_color = '#F59E0B',
       tertiary_color  = '#0F172A',
       updated_at      = NOW()
WHERE  id = 1
  AND  primary_color   = '#7A1F2B'
  AND  secondary_color = '#C9A961'
  AND  tertiary_color  = '#1A1814';

-- +goose StatementEnd

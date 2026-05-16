# Migrations

SealKeeper ships **forward-only** migrations (FR-H.61, D-D.13). Rollback is
performed by restoring a backup, not by stepping migrations down — the `down`
sections in the SQL files exist only to support local development resets.

## Layout

```
migrations/
├── postgres/    # Postgres production target (FR-H.30)
└── sqlite/      # SQLite eval / single-binary mode
```

Both dialect trees stay in lockstep on column names and semantics. Type and
default-expression differences are inevitable (`BYTEA` vs `BLOB`,
`TIMESTAMPTZ` vs `TEXT`, `NOW()` vs `CURRENT_TIMESTAMP`, sequence handling)
and are documented inside each file.

## Numbering

`NNNN_descriptor.sql` with a four-digit, zero-padded, monotonically
increasing prefix. Never reuse a number — once shipped, a migration is
immutable. If you spot a defect, ship a follow-up migration that corrects it.

## Embedded at build time

Both directories are embedded into the binary via `internal/storage` using
`go:embed`. The `migrate up` sub-command runs them through goose against the
configured DSN with the matching dialect auto-detected from the URL scheme:

| DSN scheme               | Driver       | Migration set    |
|--------------------------|--------------|------------------|
| `postgres://`, `pgx://`  | pgx (stdlib) | `postgres/`      |
| `sqlite://`, `file:`     | modernc      | `sqlite/`        |

## Local development

```bash
# Apply against an eval SQLite (default DSN when SK_MODE=eval)
./sealkeeper migrate up

# Apply against an arbitrary Postgres
SK_DATABASE_URL='postgres://sk:sk@localhost:5432/sk?sslmode=disable' \
  ./sealkeeper migrate up

# Read the current schema version
./sealkeeper migrate status
```

Goose's own `goose_db_version` book-keeping table lives alongside the schema
and is intentionally untouched by these migrations.

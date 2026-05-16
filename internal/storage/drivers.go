// Package storage — driver registration.
//
// These blank imports are the side-effect that registers the SQL drivers
// with database/sql. Splitting them out keeps storage.go focused on the
// public surface.
package storage

import (
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" driver
	_ "modernc.org/sqlite"             // registers pure-Go "sqlite" driver — no CGO
)

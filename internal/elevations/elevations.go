// Package elevations owns the per-domain B2 / B3 elevation lists.
//
// PRD: FR-C.38..46.
//
// Resolution semantics, used by policies.Resolve():
//   - if an email appears in elevations with level=B2 → B2 policy applies
//   - if an email appears with level=B3            → B3 policy applies
//   - otherwise the implicit B1 level applies (FR-C.28).
package elevations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Level enumerates the elevation tiers. B1 isn't stored — it's the default
// when an email is missing from the table.
type Level string

const (
	LevelB1 Level = "B1"
	LevelB2 Level = "B2"
	LevelB3 Level = "B3"
)

// Errors.
var (
	ErrNotFound      = errors.New("elevations: not found")
	ErrAlreadyExists = errors.New("elevations: already exists")
	ErrInvalidLevel  = errors.New("elevations: invalid level")
)

// Elevation is the row view.
type Elevation struct {
	ID               int64
	DomainID         int64
	Email            string
	Level            Level
	Reason           string
	CreatedByAdminID *int64
	CreatedAt        time.Time
	LastUsedAt       *time.Time
}

// Repo persists elevations.
type Repo struct {
	db  *sql.DB
	now func() time.Time
}

// NewRepo binds a Repo.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db, now: time.Now} }

// WithClock for tests.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// Create inserts an elevation. The email is canonicalised to lowercase and
// trimmed. Returns ErrAlreadyExists when the (domain_id, email) pair
// already has a row — admins must Delete then re-Create to change level.
func (r *Repo) Create(ctx context.Context, domainID int64, email string, level Level, reason string, adminID *int64) (Elevation, error) {
	if level != LevelB2 && level != LevelB3 {
		return Elevation{}, fmt.Errorf("%w: %q", ErrInvalidLevel, level)
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return Elevation{}, errors.New("elevations.Create: empty email")
	}
	now := r.now().UTC()
	const q = `INSERT INTO elevations
		(domain_id, email, level, reason, created_by_admin_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, rebind(r.db, q),
		domainID, email, string(level), strings.TrimSpace(reason), nullableInt(adminID), now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Elevation{}, ErrAlreadyExists
		}
		return Elevation{}, fmt.Errorf("elevations.Create: %w", err)
	}
	id, _ := res.LastInsertId()
	return Elevation{
		ID:               id,
		DomainID:         domainID,
		Email:            email,
		Level:            level,
		Reason:           reason,
		CreatedByAdminID: adminID,
		CreatedAt:        now,
	}, nil
}

// Lookup returns the level for an (domain_id, email) pair. Returns LevelB1
// and ErrNotFound when no row exists — callers usually swallow the error
// and treat it as the implicit B1.
func (r *Repo) Lookup(ctx context.Context, domainID int64, email string) (Level, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	const q = `SELECT level FROM elevations WHERE domain_id = ? AND email = ?`
	var lvl string
	err := r.db.QueryRowContext(ctx, rebind(r.db, q), domainID, email).Scan(&lvl)
	if errors.Is(err, sql.ErrNoRows) {
		return LevelB1, ErrNotFound
	}
	if err != nil {
		return LevelB1, err
	}
	return Level(lvl), nil
}

// List returns every row for the given domain, ordered by email.
func (r *Repo) List(ctx context.Context, domainID int64) ([]Elevation, error) {
	const q = selectQ + ` WHERE domain_id = ? ORDER BY email ASC`
	rows, err := r.db.QueryContext(ctx, rebind(r.db, q), domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collect(rows)
}

// ListAll returns every elevation row across every domain. Used by the
// admin /admin/elevations index page.
func (r *Repo) ListAll(ctx context.Context) ([]Elevation, error) {
	rows, err := r.db.QueryContext(ctx, selectQ+` ORDER BY domain_id, email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collect(rows)
}

// Delete removes a row by id.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, rebind(r.db, "DELETE FROM elevations WHERE id = ?"), id)
	return err
}

// Get returns a row by id.
func (r *Repo) Get(ctx context.Context, id int64) (Elevation, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+` WHERE id = ?`), id))
}

// TouchLastUsed bumps the last_used_at column. Best-effort, errors are
// ignored by the caller because this is an observability convenience.
func (r *Repo) TouchLastUsed(ctx context.Context, id int64) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE elevations SET last_used_at = ? WHERE id = ?`), now, id)
	return err
}

// ----- internals ------------------------------------------------------------

const selectQ = `SELECT id, domain_id, email, level, reason, created_by_admin_id, created_at, last_used_at FROM elevations`

type rowScanner interface{ Scan(dest ...any) error }

func scan(rs rowScanner) (Elevation, error) {
	var (
		e          Elevation
		lvl        string
		createdBy  sql.NullInt64
		createdAt  any
		lastUsedAt any
	)
	err := rs.Scan(&e.ID, &e.DomainID, &e.Email, &lvl, &e.Reason, &createdBy, &createdAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Elevation{}, ErrNotFound
	}
	if err != nil {
		return Elevation{}, err
	}
	e.Level = Level(lvl)
	if createdBy.Valid {
		v := createdBy.Int64
		e.CreatedByAdminID = &v
	}
	if t, err := toTime(createdAt); err == nil {
		e.CreatedAt = t
	}
	if lastUsedAt != nil {
		if t, err := toTime(lastUsedAt); err == nil {
			t := t
			e.LastUsedAt = &t
		}
	}
	return e, nil
}

func collect(rows *sql.Rows) ([]Elevation, error) {
	var out []Elevation
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "constraint failed")
}

func rebind(db *sql.DB, query string) string {
	if db == nil {
		return query
	}
	name := fmt.Sprintf("%T", db.Driver())
	if !strings.Contains(name, "pgx") {
		return query
	}
	var b strings.Builder
	idx := 1
	for _, r := range query {
		if r == '?' {
			fmt.Fprintf(&b, "$%d", idx)
			idx++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func toTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x.UTC(), nil
	case []byte:
		return parseTS(string(x))
	case string:
		return parseTS(x)
	case nil:
		return time.Time{}, errors.New("nil time")
	default:
		return time.Time{}, fmt.Errorf("unsupported time type %T", v)
	}
}

func parseTS(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q", s)
}

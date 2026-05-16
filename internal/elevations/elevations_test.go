package elevations_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/storage"
)

func newRepos(t *testing.T) (*elevations.Repo, *domains.Repo) {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.ToSlash(filepath.Join(dir, "e.db"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return elevations.NewRepo(s.DB()), domains.NewRepo(s.DB())
}

func TestCreateAndLookup(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	d, _ := dr.Create(ctx, "example.com", "", true, nil)
	_, err := er.Create(ctx, d.ID, "Alice@Example.com", elevations.LevelB2, "manager", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	lvl, err := er.Lookup(ctx, d.ID, "alice@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lvl != elevations.LevelB2 {
		t.Errorf("level = %q, want B2", lvl)
	}
}

func TestLookupUnknown(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	d, _ := dr.Create(context.Background(), "example.com", "", true, nil)
	lvl, err := er.Lookup(context.Background(), d.ID, "missing@example.com")
	if !errors.Is(err, elevations.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if lvl != elevations.LevelB1 {
		t.Errorf("default level = %q, want B1", lvl)
	}
}

func TestInvalidLevelRejected(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	d, _ := dr.Create(context.Background(), "example.com", "", true, nil)
	if _, err := er.Create(context.Background(), d.ID, "x@example.com", elevations.Level("B5"), "", nil); !errors.Is(err, elevations.ErrInvalidLevel) {
		t.Fatalf("err = %v, want ErrInvalidLevel", err)
	}
}

func TestDuplicateRejected(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	d, _ := dr.Create(ctx, "example.com", "", true, nil)
	if _, err := er.Create(ctx, d.ID, "x@example.com", elevations.LevelB2, "", nil); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// FR-C.39: an email is in at most one list — second Create rejected
	// regardless of level.
	if _, err := er.Create(ctx, d.ID, "x@example.com", elevations.LevelB3, "", nil); !errors.Is(err, elevations.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestListPerDomain(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	a, _ := dr.Create(ctx, "a.test", "", true, nil)
	b, _ := dr.Create(ctx, "b.test", "", true, nil)
	_, _ = er.Create(ctx, a.ID, "x@a.test", elevations.LevelB2, "", nil)
	_, _ = er.Create(ctx, b.ID, "y@b.test", elevations.LevelB3, "", nil)
	listA, _ := er.List(ctx, a.ID)
	if len(listA) != 1 || listA[0].Email != "x@a.test" {
		t.Errorf("listA = %+v", listA)
	}
	all, _ := er.ListAll(ctx)
	if len(all) != 2 {
		t.Errorf("ListAll = %d, want 2", len(all))
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	d, _ := dr.Create(ctx, "example.com", "", true, nil)
	e, _ := er.Create(ctx, d.ID, "x@example.com", elevations.LevelB2, "", nil)
	if err := er.Delete(ctx, e.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := er.Get(ctx, e.ID); !errors.Is(err, elevations.ErrNotFound) {
		t.Errorf("post-delete Get err = %v, want ErrNotFound", err)
	}
}

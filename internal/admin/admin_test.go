package admin_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/storage"
)

func newRepo(t *testing.T) *admin.Repo {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.ToSlash(filepath.Join(dir, "a.db"))
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

	// admin.NewRepo requires a cryptobox.Box — even though the management
	// tests in this file never exercise TOTP encryption, the constructor
	// asserts non-nil so we mint a throwaway 32-byte key here.
	keyBuf := make([]byte, 32)
	if _, err := rand.Read(keyBuf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	box, err := cryptobox.New(base64.StdEncoding.EncodeToString(keyBuf))
	if err != nil {
		t.Fatalf("cryptobox.New: %v", err)
	}
	return admin.NewRepo(s.DB(), box)
}

func TestCreateRejectsInvalidEmail(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	_, err := r.Create(context.Background(), "not-an-email", "supersecret-12chars")
	if !errors.Is(err, admin.ErrInvalidEmail) {
		t.Fatalf("err = %v, want ErrInvalidEmail", err)
	}
}

func TestCreateRejectsDuplicate(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	if _, err := r.Create(ctx, "ops@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := r.Create(ctx, "OPS@example.test", "supersecret-12chars")
	if !errors.Is(err, admin.ErrAlreadyExists) {
		t.Fatalf("dup Create err = %v, want ErrAlreadyExists", err)
	}
}

func TestChangeEmail(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, err := r.Create(ctx, "old@example.test", "supersecret-12chars")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.ChangeEmail(ctx, a.ID, "new@example.test"); err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	got, err := r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Email != "new@example.test" {
		t.Errorf("Email = %q, want new@example.test", got.Email)
	}
	if err := r.ChangeEmail(ctx, a.ID, "not-an-email"); !errors.Is(err, admin.ErrInvalidEmail) {
		t.Errorf("ChangeEmail invalid err = %v, want ErrInvalidEmail", err)
	}
	if err := r.ChangeEmail(ctx, 999_999, "anyone@example.test"); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("ChangeEmail missing id err = %v, want ErrNotFound", err)
	}
}

func TestChangeEmailRejectsDuplicate(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, _ := r.Create(ctx, "first@example.test", "supersecret-12chars")
	if _, err := r.Create(ctx, "second@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("Create second: %v", err)
	}
	if err := r.ChangeEmail(ctx, a.ID, "second@example.test"); !errors.Is(err, admin.ErrAlreadyExists) {
		t.Errorf("ChangeEmail dup err = %v, want ErrAlreadyExists", err)
	}
}

func TestSetDisabledLastActiveGuard(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, _ := r.Create(ctx, "only@example.test", "supersecret-12chars")

	if err := r.SetDisabled(ctx, a.ID, true); !errors.Is(err, admin.ErrLastActiveAdmin) {
		t.Fatalf("first SetDisabled err = %v, want ErrLastActiveAdmin", err)
	}
	// Add a second admin then disable the first — should succeed.
	if _, err := r.Create(ctx, "second@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("Create second: %v", err)
	}
	if err := r.SetDisabled(ctx, a.ID, true); err != nil {
		t.Fatalf("SetDisabled with backup: %v", err)
	}
}

func TestDeleteLastActiveGuard(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, _ := r.Create(ctx, "alone@example.test", "supersecret-12chars")
	if err := r.Delete(ctx, a.ID); !errors.Is(err, admin.ErrLastActiveAdmin) {
		t.Errorf("Delete last active err = %v, want ErrLastActiveAdmin", err)
	}
}

func TestListReturnsCreatedAdmins(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	for _, e := range []string{"one@example.test", "two@example.test", "three@example.test"} {
		if _, err := r.Create(ctx, e, "supersecret-12chars"); err != nil {
			t.Fatalf("Create %s: %v", e, err)
		}
	}
	list, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("List = %d rows, want 3", len(list))
	}
}

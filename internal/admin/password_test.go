package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sched75/sealkeeper/internal/admin"
)

func TestValidateAdminPassword(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		pwd  string
		ok   bool
	}{
		{"empty", "", false},
		{"too short", "Short1!Pass", false},                   // 11 chars
		{"long but one class", "aaaaaaaaaaaaaaaaaaaa", false}, // 20 lowercase
		{"long with two classes", "aaaaaaaaaaaaaaaa11", false},
		{"meets floor with 3 classes", "Strong-Admin-2026", true},
		{"meets floor with 4 classes", "Strong-Admin-2026!", true},
		{"french passphrase with digits + symbols", "Cathédrale-bronze-44", true},
		{"unicode lower + digit + space", "passe robuste 4242 administrateur", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := admin.ValidateAdminPassword(c.pwd)
			if c.ok && err != nil {
				t.Errorf("expected nil, got %v", err)
			}
			if !c.ok && err == nil {
				t.Errorf("expected ErrPasswordTooWeak, got nil")
			}
			if err != nil && !errors.Is(err, admin.ErrPasswordTooWeak) {
				t.Errorf("err = %v, want ErrPasswordTooWeak wrap", err)
			}
		})
	}
}

func TestChangePasswordRejectsWeak(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, err := r.Create(ctx, "ops@example.test", "Strong-Bootstrap-2026!")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.ChangePassword(ctx, a.ID, "short"); !errors.Is(err, admin.ErrPasswordTooWeak) {
		t.Errorf("ChangePassword(short) = %v, want ErrPasswordTooWeak", err)
	}
	if err := r.ChangePassword(ctx, a.ID, "Strong-Replacement-2026!"); err != nil {
		t.Errorf("ChangePassword(strong) = %v, want nil", err)
	}
}

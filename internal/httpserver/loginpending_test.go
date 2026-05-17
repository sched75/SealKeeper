package httpserver

import (
	"testing"
	"time"
)

func TestLoginPendingStore_IssueLookupConsume(t *testing.T) {
	t.Parallel()
	s := newLoginPendingStore(5 * time.Minute)
	tok, exp, err := s.Issue(42)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	if !exp.After(time.Now()) {
		t.Fatalf("expiry not in the future: %v", exp)
	}
	if id, ok := s.Lookup(tok); !ok || id != 42 {
		t.Errorf("Lookup id=%d ok=%v, want 42/true", id, ok)
	}
	// Lookup is non-consuming.
	if id, ok := s.Lookup(tok); !ok || id != 42 {
		t.Errorf("second Lookup id=%d ok=%v, want 42/true", id, ok)
	}
	if id, ok := s.Consume(tok); !ok || id != 42 {
		t.Errorf("Consume id=%d ok=%v, want 42/true", id, ok)
	}
	if _, ok := s.Lookup(tok); ok {
		t.Error("Lookup after Consume should miss")
	}
}

func TestLoginPendingStore_Expiry(t *testing.T) {
	t.Parallel()
	s := newLoginPendingStore(time.Minute)
	base := time.Now()
	s.now = func() time.Time { return base }
	tok, _, err := s.Issue(7)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, ok := s.Lookup(tok); ok {
		t.Error("Lookup should miss after TTL")
	}
}

func TestLoginPendingStore_EmptyToken(t *testing.T) {
	t.Parallel()
	s := newLoginPendingStore(time.Minute)
	if _, ok := s.Lookup(""); ok {
		t.Error("Lookup of empty token should miss")
	}
	if _, ok := s.Consume(""); ok {
		t.Error("Consume of empty token should miss")
	}
}

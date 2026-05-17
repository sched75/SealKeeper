package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// loginPendingStore is the in-memory bridge between password verification
// and the WebAuthn assertion. After a successful password check (and only
// when the admin has WebAuthn keys registered) we mint a short-lived token
// here, store it in an HttpOnly cookie, and redirect the browser to the
// /admin/login/webauthn page. The /begin and /finish endpoints look up
// the token to know which admin is mid-flight without re-prompting for
// the password.
//
// The store is process-local — SealKeeper currently ships as a single
// binary, and the step-up window is so short (5 min) that a clustered
// store would just be premature complexity. Migrating to Redis later is
// a swap of this single type.
type loginPendingStore struct {
	mu    sync.Mutex
	items map[string]loginPendingEntry
	ttl   time.Duration
	now   func() time.Time
}

type loginPendingEntry struct {
	adminID   int64
	expiresAt time.Time
}

func newLoginPendingStore(ttl time.Duration) *loginPendingStore {
	return &loginPendingStore{
		items: make(map[string]loginPendingEntry),
		ttl:   ttl,
		now:   time.Now,
	}
}

// Issue mints a fresh token bound to the admin row. The caller is
// expected to set it in an HttpOnly + SameSite=Strict cookie.
func (s *loginPendingStore) Issue(adminID int64) (string, time.Time, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	expires := s.now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	s.items[tok] = loginPendingEntry{adminID: adminID, expiresAt: expires}
	return tok, expires, nil
}

// Lookup returns the admin id bound to the token. The token stays valid
// for retries on /begin until either it expires or /finish consumes it.
func (s *loginPendingStore) Lookup(tok string) (int64, bool) {
	if tok == "" {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[tok]
	if !ok {
		return 0, false
	}
	if s.now().After(e.expiresAt) {
		delete(s.items, tok)
		return 0, false
	}
	return e.adminID, true
}

// Consume removes the token. Called from /finish once the WebAuthn
// assertion is verified so the same pending row cannot be replayed to
// mint a second session.
func (s *loginPendingStore) Consume(tok string) (int64, bool) {
	if tok == "" {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[tok]
	delete(s.items, tok)
	if !ok {
		return 0, false
	}
	if s.now().After(e.expiresAt) {
		return 0, false
	}
	return e.adminID, true
}

// gc drops expired entries. Called inline on Issue so the map can't
// grow without bound when /finish is never reached.
func (s *loginPendingStore) gc() {
	now := s.now()
	for k, v := range s.items {
		if now.After(v.expiresAt) {
			delete(s.items, k)
		}
	}
}

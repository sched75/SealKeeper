// Package mailcapture stores outgoing mail in memory when SealKeeper runs in
// evaluation mode (FR-H.17). It backs the /__captured_mail debug endpoint
// that the smoke tests exercise and that the admin console exposes when
// SK_MODE=eval.
package mailcapture

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Mail is a captured outbound message.
type Mail struct {
	ID        string    `json:"id"`
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
}

// Store is a small thread-safe ring buffer holding the most recent N mails.
type Store struct {
	mu     sync.RWMutex
	items  []Mail
	max    int
	nextID int
}

// NewStore returns a Store retaining at most max messages.
func NewStore(max int) *Store {
	if max <= 0 {
		max = 100
	}
	return &Store{max: max, items: make([]Mail, 0, max)}
}

// Capture records a mail and returns its assigned id.
func (s *Store) Capture(to, subject, body string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	m := Mail{
		ID:        formatID(s.nextID),
		To:        to,
		Subject:   subject,
		Body:      body,
		Timestamp: time.Now().UTC(),
	}
	if len(s.items) >= s.max {
		copy(s.items, s.items[1:])
		s.items[len(s.items)-1] = m
	} else {
		s.items = append(s.items, m)
	}
	return m.ID
}

// Snapshot returns a copy of the current items.
func (s *Store) Snapshot() []Mail {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Mail, len(s.items))
	copy(out, s.items)
	return out
}

// Handler serves the captured queue as JSON.
func (s *Store) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Items []Mail `json:"items"`
		}{Items: s.Snapshot()})
	}
}

func formatID(n int) string {
	const hex = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = hex[n&0xF]
		n >>= 4
	}
	return string(buf[i:])
}

// Package policy exposes the password policy advertised on /api/v1/policy.
//
// This is a skeleton implementation: it returns the v0.1 default policy as a
// static JSON payload. A real policy store (DB-backed, per-tenant) will land
// when the admin console is wired.
package policy

import (
	"encoding/json"
	"net/http"
)

// Policy mirrors the FR-A.* shape — kept intentionally small for the skeleton.
type Policy struct {
	Version      int      `json:"version"`
	Generators   []string `json:"generators"`
	MinEntropy   int      `json:"min_entropy_bits"`
	Length       Length   `json:"length"`
	Levels       []string `json:"levels"`
	Transforms   []string `json:"transforms"`
	UpdatedAt    string   `json:"updated_at"`
}

// Length expresses the configurable bounds.
type Length struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// Default returns the baseline policy used until a real store is wired.
func Default() Policy {
	return Policy{
		Version:    1,
		Generators: []string{"G1", "G2", "G3"},
		MinEntropy: 80,
		Length:     Length{Min: 12, Max: 64},
		Levels:     []string{"standard", "high", "very_high"},
		Transforms: []string{"T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"},
		UpdatedAt:  "1970-01-01T00:00:00Z",
	}
}

// Handler returns an http.HandlerFunc serving the default policy as JSON.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(Default())
	}
}

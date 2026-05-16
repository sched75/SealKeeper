// Package cryptobox is a thin AES-256-GCM helper used to encrypt secrets at
// rest (TOTP secret, SMTP password) using the SK_MASTER_SECRET.
//
// Why AES-256-GCM? Because it's the standard authenticated encryption
// primitive shipped in Go's stdlib, fast, has nonce-misuse caveats we manage
// here (fresh random nonce per call), and survives FIPS-140-3 review.
//
// Storage layout: `nonce (12 bytes) || ciphertext || tag (16 bytes)`. The
// nonce is prepended to the ciphertext so Open() needs only the box and the
// shared key.
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	keyLen   = 32 // AES-256
	nonceLen = 12 // 96 bits as recommended by NIST SP 800-38D
)

// Box owns the cipher state.
type Box struct {
	aead cipher.AEAD
}

// New derives a 32-byte key from masterSecret and returns a Box bound to it.
//
// `masterSecret` is interpreted as:
//   - base64-encoded raw bytes (the standard SK_MASTER_SECRET format), OR
//   - any other string, in which case sha256(string) is used so the API
//     never panics on a bad input — this is the "developer set a literal
//     master secret in dev" path.
//
// In every case the resulting key is exactly 32 bytes.
func New(masterSecret string) (*Box, error) {
	if masterSecret == "" {
		return nil, errors.New("cryptobox.New: empty master secret")
	}
	key := deriveKey(masterSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptobox.New: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptobox.New: gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext with an optional `aad` (additional authenticated
// data — bound to the ciphertext but not stored inside it). The returned
// slice contains `nonce || ciphertext || tag`.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	if b == nil || b.aead == nil {
		return nil, errors.New("cryptobox: nil box")
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cryptobox.Seal: nonce: %w", err)
	}
	// Pre-allocate to avoid reallocation inside Seal.
	out := make([]byte, 0, nonceLen+len(plaintext)+b.aead.Overhead())
	out = append(out, nonce...)
	out = b.aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// Open decrypts a value produced by Seal. The same `aad` must be supplied or
// the operation fails.
func (b *Box) Open(box, aad []byte) ([]byte, error) {
	if b == nil || b.aead == nil {
		return nil, errors.New("cryptobox: nil box")
	}
	if len(box) < nonceLen+b.aead.Overhead() {
		return nil, errors.New("cryptobox.Open: box too short")
	}
	nonce, ct := box[:nonceLen], box[nonceLen:]
	pt, err := b.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("cryptobox.Open: %w", err)
	}
	return pt, nil
}

// deriveKey ensures we always feed AES-256 with a 32-byte key, regardless of
// how the master secret was provided.
func deriveKey(masterSecret string) []byte {
	if raw, err := base64.StdEncoding.DecodeString(masterSecret); err == nil && len(raw) == keyLen {
		return raw
	}
	if raw, err := base64.RawStdEncoding.DecodeString(masterSecret); err == nil && len(raw) == keyLen {
		return raw
	}
	if raw, err := base64.URLEncoding.DecodeString(masterSecret); err == nil && len(raw) == keyLen {
		return raw
	}
	if raw, err := base64.RawURLEncoding.DecodeString(masterSecret); err == nil && len(raw) == keyLen {
		return raw
	}
	sum := sha256.Sum256([]byte(masterSecret))
	return sum[:]
}

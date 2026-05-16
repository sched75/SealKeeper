package cryptobox_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/sched75/sealkeeper/internal/cryptobox"
)

func TestRoundTripWithBase64MasterSecret(t *testing.T) {
	t.Parallel()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))
	box, err := cryptobox.New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	plain := []byte("totp-secret-bytes")
	aad := []byte("admin:1")
	ct, err := box.Seal(plain, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	pt, err := box.Open(ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(plain, pt) {
		t.Fatalf("round-trip mismatch: %q vs %q", plain, pt)
	}
}

func TestRoundTripWithPlainStringSecret(t *testing.T) {
	t.Parallel()
	// Non-base64 input → falls back to sha256 of the string.
	box, err := cryptobox.New("not really base64 just a passphrase")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pt := []byte("hello")
	ct, err := box.Seal(pt, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := box.Open(ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("got %q", got)
	}
}

func TestAADMismatchFailsOpen(t *testing.T) {
	t.Parallel()
	box, _ := cryptobox.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	ct, _ := box.Seal([]byte("x"), []byte("a"))
	if _, err := box.Open(ct, []byte("b")); err == nil {
		t.Fatal("expected Open to fail with wrong AAD")
	}
}

func TestEmptyMasterSecretRejected(t *testing.T) {
	t.Parallel()
	if _, err := cryptobox.New(""); err == nil {
		t.Fatal("expected error for empty master secret")
	}
}

func TestNoncesAreFresh(t *testing.T) {
	t.Parallel()
	box, _ := cryptobox.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	a, _ := box.Seal([]byte("payload"), nil)
	b, _ := box.Seal([]byte("payload"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two Seal calls produced identical ciphertext — nonce reuse")
	}
}

func TestShortBoxRejected(t *testing.T) {
	t.Parallel()
	box, _ := cryptobox.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if _, err := box.Open([]byte("short"), nil); err == nil {
		t.Fatal("expected Open to reject too-short input")
	}
}

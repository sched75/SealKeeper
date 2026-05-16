package totp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/totp"
)

// RFC 6238 Appendix B sample vector — Key "12345678901234567890" (ASCII),
// algorithm SHA-1, at T0 = 0 + 59s → code 94287082 (8 digits) which truncates
// to "287082" for a 6-digit token.
func TestRFC6238SampleVector(t *testing.T) {
	t.Parallel()
	// ASCII secret "12345678901234567890" → base32 (no padding):
	// GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
	secret := totp.Secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	at := time.Unix(59, 0).UTC()
	code, err := totp.Generate(secret, at)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if code != "287082" {
		t.Fatalf("code = %q, want 287082 (RFC 6238 sample @ t=59)", code)
	}
}

func TestVerifyAcceptsWithinDriftWindow(t *testing.T) {
	t.Parallel()
	secret, err := totp.NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	now := time.Now().UTC()

	// Current window.
	code, _ := totp.Generate(secret, now)
	if ok, _ := totp.Verify(secret, code, now); !ok {
		t.Error("current code rejected")
	}

	// 30s earlier (counter -1) — must still verify (drift window ±1).
	codePrev, _ := totp.Generate(secret, now.Add(-30*time.Second))
	if ok, _ := totp.Verify(secret, codePrev, now); !ok {
		t.Error("t-1 code rejected (drift window broken)")
	}

	// 60s earlier (counter -2) — must NOT verify.
	codeFar, _ := totp.Generate(secret, now.Add(-65*time.Second))
	if ok, _ := totp.Verify(secret, codeFar, now); ok {
		t.Error("t-2 code accepted (drift window too wide)")
	}
}

func TestVerifyRejectsWrongCode(t *testing.T) {
	t.Parallel()
	secret, _ := totp.NewSecret()
	ok, _ := totp.Verify(secret, "000000", time.Now())
	if ok {
		t.Fatal("000000 should never verify for a fresh secret")
	}
}

func TestVerifyRejectsBadFormat(t *testing.T) {
	t.Parallel()
	secret, _ := totp.NewSecret()
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		ok, _ := totp.Verify(secret, bad, time.Now())
		if ok {
			t.Errorf("verify accepted %q", bad)
		}
	}
}

func TestOtpauthURLShape(t *testing.T) {
	t.Parallel()
	secret := totp.Secret("JBSWY3DPEHPK3PXP")
	url := totp.Otpauth(secret, "SealKeeper", "alice@example.com")
	// `@` is a reserved-but-allowed character in URL path segments per RFC
	// 3986; url.PathEscape leaves it as-is on purpose.
	if !strings.HasPrefix(url, "otpauth://totp/SealKeeper:alice@example.com?") {
		t.Errorf("unexpected URL: %s", url)
	}
	for _, want := range []string{"secret=JBSWY3DPEHPK3PXP", "issuer=SealKeeper", "digits=6", "period=30", "algorithm=SHA1"} {
		if !strings.Contains(url, want) {
			t.Errorf("URL missing %q: %s", want, url)
		}
	}
}

func TestRecoveryCodesUnique(t *testing.T) {
	t.Parallel()
	codes, err := totp.NewRecoveryCodes(8)
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	if len(codes) != 8 {
		t.Fatalf("got %d codes, want 8", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate %q", c)
		}
		seen[c] = true
		if len(c) != 11 || c[5] != '-' {
			t.Errorf("malformed code %q", c)
		}
	}
}

func TestConsumeRecovery(t *testing.T) {
	t.Parallel()
	codes := []string{"AAA00-BBB11", "CCC22-DDD33"}
	next, ok := totp.ConsumeRecovery(codes, "aaa00-bbb11")
	if !ok {
		t.Fatal("ConsumeRecovery missed a real code")
	}
	if len(next) != 1 || next[0] != "CCC22-DDD33" {
		t.Errorf("after consume = %v", next)
	}
	// Second attempt with the same code → no match.
	if _, ok := totp.ConsumeRecovery(next, "AAA00-BBB11"); ok {
		t.Fatal("ConsumeRecovery returned true for a code that was already burnt")
	}
}

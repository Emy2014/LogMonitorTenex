package mfa

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptRoundTrip(t *testing.T) {
	k := key(t)
	sealed, err := Encrypt("JBSWY3DPEHPK3PXP", k)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if strings.Contains(string(sealed), "JBSWY3DPEHPK3PXP") {
		t.Fatal("plaintext secret is visible in the ciphertext")
	}
	got, err := Decrypt(sealed, k)
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round trip failed: %q %v", got, err)
	}
}

// AES-GCM is authenticated; a tampered ciphertext must fail rather than
// silently decrypt to garbage that then gets used as a TOTP secret.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	k := key(t)
	sealed, _ := Encrypt("JBSWY3DPEHPK3PXP", k)
	sealed[len(sealed)-1] ^= 0xff
	if _, err := Decrypt(sealed, k); err == nil {
		t.Fatal("tampered ciphertext must not decrypt")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	sealed, _ := Encrypt("JBSWY3DPEHPK3PXP", key(t))
	if _, err := Decrypt(sealed, key(t)); err == nil {
		t.Fatal("a different key must not decrypt")
	}
}

func TestEncryptRequiresFullLengthKey(t *testing.T) {
	if _, err := Encrypt("x", []byte("short")); err == nil {
		t.Fatal("a short key must be rejected, not silently padded")
	}
}

func TestValidateReturnsCodeAsReplayKey(t *testing.T) {
	secret, _, err := GenerateSecret("analyst@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	ok, replayKey, err := Validate(code, secret)
	if err != nil || !ok {
		t.Fatalf("current code should validate: ok=%v err=%v", ok, err)
	}
	// The returned value is the replay key, so it must be the code itself --
	// keying on a wall-clock step leaves a skew-accepted code reusable across
	// the boundary.
	if replayKey != code {
		t.Fatalf("replay key = %q, want the code %q", replayKey, code)
	}
}

func TestValidateRejectsWrongCode(t *testing.T) {
	secret, _, _ := GenerateSecret("analyst@example.com")
	if ok, _, _ := Validate("000000", secret); ok {
		// 1-in-a-million false positive is possible; regenerate and retry once.
		if ok2, _, _ := Validate("000000", mustOtherSecret(t)); ok2 {
			t.Fatal("an arbitrary code validated against two secrets")
		}
	}
}

func mustOtherSecret(t *testing.T) string {
	t.Helper()
	s, _, err := GenerateSecret("other@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A code from far outside the skew window must not be accepted; otherwise a
// phished code stays usable long after it was captured.
func TestValidateRejectsStaleCode(t *testing.T) {
	secret, _, _ := GenerateSecret("analyst@example.com")
	stale, err := totp.GenerateCode(secret, time.Now().Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := Validate(stale, secret); ok {
		t.Fatal("a ten-minute-old code must not validate")
	}
}

func TestRecoveryCodesAreDistinctAndTranscribable(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeQty {
		t.Fatalf("want %d codes, got %d", RecoveryCodeQty, len(codes))
	}

	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[c] = true

		// These get written down and typed back under stress. Characters that
		// are easily confused would make a code fail exactly when it matters.
		for _, ch := range c {
			if strings.ContainsRune("ILO01", ch) {
				t.Fatalf("code %q contains an ambiguous character %q", c, ch)
			}
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	if got := NormalizeRecoveryCode("  abcd efgh-2345 6789 "); got != "ABCDEFGH-23456789" {
		t.Fatalf("got %q", got)
	}
}

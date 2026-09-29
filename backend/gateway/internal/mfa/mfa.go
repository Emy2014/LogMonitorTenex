// Package mfa implements TOTP enrolment, verification and recovery codes.
package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	Issuer          = "LogMonitor"
	RecoveryCodeQty = 10
	// A TOTP step is 30s. Allowing one step either side absorbs clock drift
	// between the phone and the server; more than that widens the window an
	// attacker has to land a phished code.
	skewSteps = 1
)

var ErrNoKey = errors.New("TOTP_ENCRYPTION_KEY is not configured")

// GenerateSecret returns a new base32 TOTP secret and its provisioning URI.
func GenerateSecret(accountEmail string) (secret, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: accountEmail,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // what authenticator apps universally support
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// Validate reports whether code is currently valid for secret, returning the
// normalised code for use as a replay key.
//
// The key is the code itself, not the current time step. Skew means a code
// from the neighbouring step is also accepted, so recording the wall-clock
// step would leave such a code usable again once the clock rolled over --
// exactly at the boundary, which is when it matters.
func Validate(code, secret string) (bool, string, error) {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period: 30, Skew: skewSteps, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return false, "", err
	}
	return true, code, nil
}

// --- secret encryption at rest ---------------------------------------------

// Encrypt seals a TOTP secret with AES-GCM. A TOTP secret is a password
// equivalent: whoever holds it can mint valid codes indefinitely, so a database
// dump must not hand it over.
func Encrypt(secret string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrNoKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(secret), nil), nil
}

func Decrypt(sealed, key []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrNoKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// --- recovery codes ---------------------------------------------------------

var codeAlphabet = base32.NewEncoding("ABCDEFGHJKMNPQRSTUVWXYZ23456789!").WithPadding(base32.NoPadding)

// GenerateRecoveryCodes returns human-transcribable single-use codes.
//
// The alphabet omits I, L, O, 0 and 1 -- these get written on paper and typed
// back under stress, and a code that cannot be read reliably is a code that
// does not work when it is actually needed.
func GenerateRecoveryCodes() ([]string, error) {
	out := make([]string, 0, RecoveryCodeQty)
	for i := 0; i < RecoveryCodeQty; i++ {
		buf := make([]byte, 10)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, err
		}
		s := codeAlphabet.EncodeToString(buf)
		s = strings.ReplaceAll(s, "!", "7")
		out = append(out, fmt.Sprintf("%s-%s", s[:8], s[8:16]))
	}
	return out, nil
}

func NormalizeRecoveryCode(s string) string {
	return strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(s, " ", "")))
}

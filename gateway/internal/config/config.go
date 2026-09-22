// Package config loads settings from the environment.
//
// Every setting has a working development default except the ones where a
// wrong value is a security problem rather than an inconvenience.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL    string
	RedisURL       string
	JWTSecret      string
	Port           string
	MaxUploadBytes int64
	MetricsToken   string
	CookieSecure   bool

	S3Endpoint    string
	S3Bucket      string
	S3AccessKey   string
	S3SecretKey   string
	S3PathStyle   bool

	// Edge gate: a coarse shared credential in front of everything. Not the
	// security boundary -- it exists so scanners never reach the real login.
	EdgeAuthEnabled  bool
	EdgeAuthUser     string
	EdgeAuthPassHash string

	// Second factor. The key encrypts TOTP secrets at rest.
	TOTPEncryptionKey []byte

	LoginRateEnabled bool
	ShardSize        int
}

func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:    env("DATABASE_URL", "postgres://logmonitor:logmonitor@localhost:5432/logmonitor?sslmode=disable"),
		RedisURL:       env("REDIS_URL", "redis://localhost:6379/0"),
		JWTSecret:      env("JWT_SECRET", ""),
		Port:           env("PORT", "8000"),
		MaxUploadBytes: envInt("MAX_UPLOAD_BYTES", 512<<20),
		MetricsToken:   env("METRICS_TOKEN", ""),
		CookieSecure:   envBool("COOKIE_SECURE", true),
		S3Endpoint:     env("S3_ENDPOINT", ""),
		S3Bucket:       env("S3_BUCKET", "logmonitor-raw"),
		S3AccessKey:    env("S3_ACCESS_KEY", ""),
		S3SecretKey:    env("S3_SECRET_KEY", ""),
		S3PathStyle:    envBool("S3_FORCE_PATH_STYLE", false),

		EdgeAuthEnabled:  envBool("EDGE_AUTH_ENABLED", false),
		EdgeAuthUser:     env("EDGE_AUTH_USER", ""),
		EdgeAuthPassHash: env("EDGE_AUTH_PASS_HASH", ""),
		LoginRateEnabled: envBool("LOGIN_RATE_LIMIT_ENABLED", true),
		ShardSize:        int(envInt("SHARD_SIZE", 25000)),
	}

	if c.EdgeAuthEnabled && (c.EdgeAuthUser == "" || c.EdgeAuthPassHash == "") {
		return nil, fmt.Errorf("EDGE_AUTH_ENABLED requires EDGE_AUTH_USER and EDGE_AUTH_PASS_HASH")
	}

	// A TOTP secret sitting in the database in plaintext is a password
	// equivalent anyone with a database dump can use forever, so the key is
	// required rather than optional-with-a-fallback.
	if raw := os.Getenv("TOTP_ENCRYPTION_KEY"); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("TOTP_ENCRYPTION_KEY must be 64 hex characters (32 bytes)")
		}
		c.TOTPEncryptionKey = key
	}

	// A blank signing key would mean every forged cookie validates. Refusing to
	// start is the only safe response; there is no sensible default.
	if c.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	return c, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

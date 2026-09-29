// Package ratelimit throttles credential-guessing against the login endpoint.
//
// Two dimensions, deliberately asymmetric:
//
//	by IP       tight window, the primary control. A client hammering the
//	            endpoint is throttled regardless of which accounts it targets.
//	by account  long window with a capped lock. Secondary, because per-account
//	            lockout is a denial-of-service primitive: anyone who knows an
//	            email could otherwise lock its owner out at will.
//
// The two also fail differently on purpose, and that is the subtle part. An IP
// throttle answers 429 -- it says nothing about whether any account exists. An
// account lock answers with the *same* 401 and body as a wrong password,
// because a distinguishable "this account is locked" is an existence oracle,
// and it would undo the equal-response work in the login handler.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// Tuned so an ordinary person fumbling their password is never affected,
	// while an automated guesser is stopped within seconds.
	ipLimit     = 20
	ipWindow    = 5 * time.Minute
	acctLimit   = 10
	acctWindow  = 30 * time.Minute
	// A lock that never lifts turns a nuisance into a permanent outage for the
	// victim, so it expires with the window rather than needing an unlock.
	lockDuration = 15 * time.Minute
)

type Decision struct {
	Allowed       bool
	IPThrottled   bool // -> 429, reveals nothing about accounts
	AccountLocked bool // -> identical 401, must stay indistinguishable
	RetryAfter    time.Duration
}

type Limiter struct {
	rdb *redis.Client
	log *slog.Logger
}

func New(redisURL string, log *slog.Logger) (*Limiter, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &Limiter{rdb: redis.NewClient(opt), log: log}, nil
}

func (l *Limiter) Close() error { return l.rdb.Close() }

func (l *Limiter) Ping(ctx context.Context) error { return l.rdb.Ping(ctx).Err() }

// accountKey hashes the email so a Redis dump is not a user list.
func accountKey(account string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(account))))
	return "rl:acct:" + hex.EncodeToString(sum[:8])
}

func ipKey(ip string) string { return "rl:ip:" + ip }

// Check reports whether an attempt may proceed.
//
// On a Redis failure it allows the attempt and logs loudly. Failing closed
// would turn a cache outage into a total authentication outage, and the
// password check still stands behind this; failing open loses a defence in
// depth layer, which is the lesser harm. The log line is how that gets noticed.
func (l *Limiter) Check(ctx context.Context, ip, account string) Decision {
	allow := Decision{Allowed: true}

	ipCount, err := l.rdb.Get(ctx, ipKey(ip)).Int()
	if err != nil && err != redis.Nil {
		l.log.Error("rate limiter unavailable; allowing attempt",
			"event", "ratelimit.unavailable", "err", err)
		return allow
	}
	if ipCount >= ipLimit {
		ttl, _ := l.rdb.TTL(ctx, ipKey(ip)).Result()
		return Decision{IPThrottled: true, RetryAfter: ttl}
	}

	locked, err := l.rdb.Exists(ctx, accountKey(account)+":lock").Result()
	if err != nil && err != redis.Nil {
		return allow
	}
	if locked > 0 {
		return Decision{AccountLocked: true}
	}
	return allow
}

// RecordFailure counts one failed attempt against both dimensions.
func (l *Limiter) RecordFailure(ctx context.Context, ip, account string) {
	pipe := l.rdb.TxPipeline()

	ik := ipKey(ip)
	pipe.Incr(ctx, ik)
	// NX so the window is anchored to the first failure and cannot be extended
	// indefinitely by continued attempts.
	pipe.ExpireNX(ctx, ik, ipWindow)

	ak := accountKey(account)
	acct := pipe.Incr(ctx, ak)
	pipe.ExpireNX(ctx, ak, acctWindow)

	if _, err := pipe.Exec(ctx); err != nil {
		l.log.Error("rate limiter write failed",
			"event", "ratelimit.write_failed", "err", err)
		return
	}

	if acct.Val() >= acctLimit {
		if err := l.rdb.Set(ctx, ak+":lock", "1", lockDuration).Err(); err != nil {
			l.log.Error("lock write failed", "event", "ratelimit.lock_failed", "err", err)
		}
	}
}

// Reset clears an account's counters after a successful authentication. The IP
// counter is left alone: a shared NAT egress should not have its budget
// refilled by one person logging in correctly.
func (l *Limiter) Reset(ctx context.Context, account string) {
	ak := accountKey(account)
	if err := l.rdb.Del(ctx, ak, ak+":lock").Err(); err != nil {
		l.log.Error("rate limiter reset failed", "event", "ratelimit.reset_failed", "err", err)
	}
}

// Consume marks a single-use token as spent, returning false if it was already
// used. Backs TOTP replay protection, where a code stays valid for a ~30s
// window and must not be accepted twice inside it.
func (l *Limiter) Consume(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return l.rdb.SetNX(ctx, "used:"+key, "1", ttl).Result()
}

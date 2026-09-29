// Command gateway is the LogMonitor HTTP API: authentication, organizations,
// access grants, log ingestion and every dashboard read query.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"log/slog"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/authz"
	"github.com/logmonitor/gateway/internal/blob"
	"github.com/logmonitor/gateway/internal/config"
	"github.com/logmonitor/gateway/internal/handlers"
	"github.com/logmonitor/gateway/internal/migrations"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/obs"
	"github.com/logmonitor/gateway/internal/queue"
	"github.com/logmonitor/gateway/internal/ratelimit"
	"github.com/logmonitor/gateway/internal/store"
)

func main() {
	// The container healthcheck runs this binary rather than shipping curl into
	// a distroless image just to probe a port.
	healthcheck := flag.Bool("healthcheck", false, "probe the local health endpoint and exit")
	migrateOnly := flag.Bool("migrate", false, "apply database migrations and exit")
	flag.Parse()
	if *healthcheck {
		os.Exit(probe())
	}
	if *migrateOnly {
		if err := runMigrations(); err != nil {
			fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// runMigrations is the entry point for the migration job. Same binary, same
// embedded SQL as the service -- there is no second artifact to keep in step.
func runMigrations() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := obs.NewLogger(os.Getenv("LOG_LEVEL"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	applied, err := migrations.Up(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	log.Info("migrations applied", "event", "migrate.done", "count", applied)
	return nil
}

func probe() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/api/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := obs.NewLogger(os.Getenv("LOG_LEVEL"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := connectWithRetry(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer st.Close()

	limiter, err := ratelimit.New(cfg.RedisURL, log)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	defer func() { _ = limiter.Close() }()
	if err := limiter.Ping(ctx); err != nil {
		// Not fatal. The limiter fails open by design, and refusing to boot
		// over an unavailable cache would turn a degraded defence into a
		// total authentication outage.
		log.Error("redis unreachable; login rate limiting is degraded",
			"event", "redis.unreachable", "err", err)
	}

	// Object storage is required for ingest: losing the raw bytes is what v1
	// did, and it is unrecoverable. Failing to reach the bucket is logged
	// rather than fatal, so the rest of the API still serves.
	var archive blob.Store
	if cfg.S3Bucket != "" {
		archive, err = blob.New(ctx, blob.Config{
			Bucket:    cfg.S3Bucket,
			Endpoint:  cfg.S3Endpoint, // empty => native GCS
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			PathStyle: cfg.S3PathStyle,
		})
		if err != nil {
			return fmt.Errorf("object storage: %w", err)
		}
		if err := archive.Ping(ctx); err != nil {
			log.Error("object storage unreachable; uploads will be refused",
				"event", "blob.unreachable", "store", archive.Describe(), "err", err)
		} else {
			log.Info("object storage ready", "event", "blob.ready", "store", archive.Describe())
		}
	} else {
		log.Warn("S3_BUCKET is unset; uploads will be refused", "event", "blob.unconfigured")
	}

	publisher, err := queue.New(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}
	defer func() { _ = publisher.Close() }()

	api := &handlers.API{
		Cfg:     cfg,
		Store:   st,
		Auth:    auth.NewManager(cfg.JWTSecret, cfg.CookieSecure, st),
		Authz:   authz.New(st, log),
		Limiter: limiter,
		Blob:    archive,
		Queue:   publisher,
		Log:     log,
	}

	// Outermost first. The edge gate runs before anything else so an
	// unauthenticated scanner never reaches the login handler, let alone the
	// database. Health is exempt from both gates or the container probe fails.
	exempt := map[string]bool{"/api/health": true}
	handler := obs.Middleware(log)(
		httpx.SecurityHeaders(
			httpx.BasicAuth(cfg.EdgeAuthEnabled, cfg.EdgeAuthUser, cfg.EdgeAuthPassHash,
				auth.VerifyPassword, exempt)(
				httpx.CSRF(cfg.CookieSecure, exempt)(
					api.Routes(),
				),
			),
		),
	)

	srv := &http.Server{
		Addr:    net.JoinHostPort("0.0.0.0", cfg.Port),
		Handler: handler,
		// No WriteTimeout: uploads stream, and a large one legitimately takes
		// longer than any value that would be safe for ordinary requests.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	go func() {
		log.Info("gateway listening", "event", "server.start", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "event", "server.failed", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down", "event", "server.stopping")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// connectWithRetry tolerates Postgres not being ready yet. Compose gates on a
// healthcheck, but a migration container finishing is not the same as the
// server accepting connections, and crash-looping on that race is noise.
func connectWithRetry(ctx context.Context, url string, log *slog.Logger) (*store.Store, error) {
	var lastErr error
	for attempt := 1; attempt <= 10; attempt++ {
		st, err := store.New(ctx, url)
		if err == nil {
			return st, nil
		}
		lastErr = err
		log.Warn("database not ready, retrying", "event", "db.retry", "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("database unreachable after retries: %w", lastErr)
}

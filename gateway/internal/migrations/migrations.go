// Package migrations applies the database schema.
//
// The SQL is embedded in the binary rather than mounted, so the image that
// serves traffic and the image that migrates are the same artifact. That
// removes a whole class of "the container had stale migrations" problem, and
// it means local development and Cloud Run run identical code.
package migrations

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed all:sql
var files embed.FS

// mustParse is separated so a malformed URL fails with a clear message rather
// than inside the driver.
func mustParse(databaseURL string) *pgx.ConnConfig {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		panic(fmt.Sprintf("DATABASE_URL: %v", err))
	}
	return cfg
}

// Up applies every pending migration and reports how many ran.
//
// golang-migrate holds an advisory lock for the duration, so concurrent
// callers cannot interleave. This still runs as a discrete job rather than at
// service startup: a failed migration should fail a job, not take the API
// down, and several starting instances should not race to own the schema.
func Up(ctx context.Context, databaseURL string) (int, error) {
	src, err := iofs.New(files, "sql")
	if err != nil {
		return 0, err
	}

	// A plain database/sql handle, not a pgxpool.
	//
	// Wrapping a pool and then closing both hangs on exit: pgxpool.Close waits
	// for every connection to be released, and the sql.DB wrapper is still
	// holding one. Migration needs exactly one connection anyway.
	db := stdlib.OpenDB(*mustParse(databaseURL))
	defer func() { _ = db.Close() }()

	if err := db.PingContext(ctx); err != nil {
		return 0, fmt.Errorf("connecting: %w", err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return 0, err
	}

	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return 0, err
	}

	before, _, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return 0, err
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return 0, fmt.Errorf("applying migrations: %w", err)
	}

	after, dirty, err := m.Version()
	if err != nil {
		return 0, err
	}
	// A dirty schema means a migration failed partway. Continuing would run
	// the next one against a half-applied state, so stop and say so.
	if dirty {
		return 0, fmt.Errorf("schema is dirty at version %d; resolve it before deploying", after)
	}
	return int(after) - int(before), nil
}

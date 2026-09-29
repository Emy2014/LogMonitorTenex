// Package store owns the database types and every query the gateway runs.
//
// Queries live here rather than in handlers so that the ownership and
// org-scoping predicates are written once, in one file per resource, where they
// can be read together and audited. The v1 code scattered `WHERE user_id = ...`
// across routers; one omission there is a data leak.
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ Pool *pgxpool.Pool }

func New(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	// Bounded on purpose. The v1 engine took SQLAlchemy's defaults with no
	// sizing at all, which is fine until a worker pool and a gateway compete
	// for the same Postgres.
	cfg.MaxConns = 16
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() { s.Pool.Close() }

// --- domain types ----------------------------------------------------------

type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
	RoleOwner  Role = "owner"
)

// IsAdmin reports whether the role carries org-wide administrative reach.
// Owner is an admin that additionally cannot be demoted by another admin.
func (r Role) IsAdmin() bool { return r == RoleAdmin || r == RoleOwner }

type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID           uuid.UUID `json:"id"`
	OrgID        uuid.UUID `json:"org_id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // never serialised
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type Upload struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	UserID      uuid.UUID `json:"user_id"`
	Filename    string    `json:"filename"`
	ByteSize    int64     `json:"byte_size"`
	LineCount   int       `json:"line_count"`
	ParsedCount int       `json:"parsed_count"`
	Format      string    `json:"format"`
	ObjectKey   string    `json:"-"` // internal bucket path; not a client concern
	CreatedAt   time.Time `json:"created_at"`
}

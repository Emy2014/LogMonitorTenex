package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrEmailTaken    = errors.New("email already registered")
	ErrSlugTaken     = errors.New("organization slug already taken")
	ErrLastOwner     = errors.New("cannot remove the last owner of an organization")
)

const userCols = `id, org_id, email, password_hash, role, created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.Pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	// email is citext, so this matches case-insensitively in the database
	// rather than relying on every caller to lowercase first.
	return scanUser(s.Pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

// CreateOrgWithOwner registers a new organization and its first user, who is
// the owner. Both rows or neither.
func (s *Store) CreateOrgWithOwner(ctx context.Context, orgName, slug, email, passwordHash string) (*Organization, *User, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var org Organization
	err = tx.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $2)
		 RETURNING id, name, slug, created_at`, orgName, slug,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.CreatedAt)
	if err != nil {
		return nil, nil, mapConstraint(err)
	}

	u, err := scanUser(tx.QueryRow(ctx,
		`INSERT INTO users (org_id, email, password_hash, role)
		 VALUES ($1, $2, $3, 'owner') RETURNING `+userCols,
		org.ID, email, passwordHash))
	if err != nil {
		return nil, nil, mapConstraint(err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return &org, u, nil
}

// CreateMember adds a user to an existing organization.
func (s *Store) CreateMember(ctx context.Context, orgID uuid.UUID, email, passwordHash string, role Role) (*User, error) {
	u, err := scanUser(s.Pool.QueryRow(ctx,
		`INSERT INTO users (org_id, email, password_hash, role)
		 VALUES ($1, $2, $3, $4) RETURNING `+userCols,
		orgID, email, passwordHash, role))
	if err != nil {
		return nil, mapConstraint(err)
	}
	return u, nil
}

// ListOrgUsers returns every user in one organization.
func (s *Store) ListOrgUsers(ctx context.Context, orgID uuid.UUID) ([]User, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+userCols+` FROM users WHERE org_id = $1 ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) OrgByID(ctx context.Context, id uuid.UUID) (*Organization, error) {
	var o Organization
	err := s.Pool.QueryRow(ctx,
		`SELECT id, name, slug, created_at FROM organizations WHERE id = $1`, id,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &o, err
}

// mapConstraint turns a unique-violation into a typed error the handler can
// translate into a useful message, instead of a bare 500.
func mapConstraint(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return err
	}
	switch pgErr.ConstraintName {
	case "users_email_key":
		return ErrEmailTaken
	case "organizations_slug_key":
		return ErrSlugTaken
	default:
		return fmt.Errorf("%w: %s", ErrEmailTaken, pgErr.ConstraintName)
	}
}

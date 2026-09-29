package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrNoRecoveryCode = errors.New("no matching unused recovery code")

// MFAState is what login needs to know about a user's second factor.
type MFAState struct {
	Enabled    bool
	Secret     []byte // encrypted; nil when not enrolled
	OrgRequire bool
}

func (s *Store) MFAState(ctx context.Context, userID uuid.UUID) (MFAState, error) {
	var m MFAState
	err := s.Pool.QueryRow(ctx, `
		SELECT u.totp_enabled, u.totp_secret, o.require_mfa
		  FROM users u JOIN organizations o ON o.id = u.org_id
		 WHERE u.id = $1`, userID).Scan(&m.Enabled, &m.Secret, &m.OrgRequire)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// StagePendingSecret stores an encrypted secret without enabling MFA.
//
// Enrolment is two steps on purpose: a secret written straight to
// totp_enabled = true would lock the user out if they never finished scanning
// the QR code.
func (s *Store) StagePendingSecret(ctx context.Context, userID uuid.UUID, sealed []byte) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE users SET totp_secret = $2, totp_enabled = false, totp_confirmed_at = NULL
		 WHERE id = $1`, userID, sealed)
	return err
}

// ActivateMFA flips the switch and replaces the recovery codes atomically.
func (s *Store) ActivateMFA(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE users SET totp_enabled = true, totp_confirmed_at = now()
		 WHERE id = $1 AND totp_secret IS NOT NULL`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DisableMFA clears the secret and every recovery code.
func (s *Store) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_confirmed_at = NULL
		 WHERE id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UnusedRecoveryHashes returns the candidate hashes for a verify attempt.
// Recovery codes are argon2id-hashed, so matching means testing each one --
// there is no lookup by value, which is the point.
func (s *Store) UnusedRecoveryHashes(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT id, code_hash FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[uuid.UUID]string{}
	for rows.Next() {
		var id uuid.UUID
		var h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, err
		}
		out[id] = h
	}
	return out, rows.Err()
}

// BurnRecoveryCode marks one code used. The WHERE clause carries the
// used_at IS NULL check so two concurrent requests cannot both spend it.
func (s *Store) BurnRecoveryCode(ctx context.Context, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx,
		`UPDATE mfa_recovery_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRecoveryCode
	}
	return nil
}

func (s *Store) SetOrgRequireMFA(ctx context.Context, orgID uuid.UUID, required bool) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE organizations SET require_mfa = $2 WHERE id = $1`, orgID, required)
	return err
}

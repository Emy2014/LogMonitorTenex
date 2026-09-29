package authz_test

import (
	"context"
	"fmt"
	"log/slog"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/authz"
	"github.com/logmonitor/gateway/internal/store"
)

// These tests run against a real Postgres. The v1 suite had no database
// fixture at all and tested only pure functions, which meant every SQL
// predicate -- including every ownership check -- was untested. For an
// authorization layer that is the one thing worth paying an integration test
// for: the rules live half in Go and half in SQL, and only a real database
// exercises both.

var testStore *store.Store

func TestMain(m *testing.M) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		fmt.Fprintln(os.Stderr, "TEST_DATABASE_URL not set; skipping authz integration tests")
		os.Exit(0)
	}
	ctx := context.Background()
	var err error
	testStore, err = store.New(ctx, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach test database: %v\n", err)
		os.Exit(1)
	}
	defer testStore.Close()
	os.Exit(m.Run())
}

type fixture struct {
	org      uuid.UUID
	owner    *store.User // uploaded the file
	peer     *store.User // same org, plain member, no grant
	admin    *store.User // same org, admin
	outsider *store.User // different org
	upload   uuid.UUID
	resolver *authz.Resolver
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	n := uuid.NewString()[:8]

	_, owner, err := testStore.CreateOrgWithOwner(ctx, "Org "+n, "org-"+n, "owner-"+n+"@t.io", "x")
	must(t, err)
	peer, err := testStore.CreateMember(ctx, owner.OrgID, "peer-"+n+"@t.io", "x", store.RoleMember)
	must(t, err)
	admin, err := testStore.CreateMember(ctx, owner.OrgID, "admin-"+n+"@t.io", "x", store.RoleAdmin)
	must(t, err)

	_, outsider, err := testStore.CreateOrgWithOwner(ctx, "Other "+n, "other-"+n, "out-"+n+"@t.io", "x")
	must(t, err)

	var uploadID uuid.UUID
	err = testStore.Pool.QueryRow(ctx,
		`INSERT INTO uploads (org_id, user_id, filename, byte_size, format, object_key)
		 VALUES ($1,$2,'z.log',1,'zscaler_nss','k') RETURNING id`,
		owner.OrgID, owner.ID).Scan(&uploadID)
	must(t, err)

	t.Cleanup(func() {
		_, _ = testStore.Pool.Exec(ctx, `DELETE FROM organizations WHERE id = ANY($1)`,
			[]uuid.UUID{owner.OrgID, outsider.OrgID})
	})

	return &fixture{
		org: owner.OrgID, owner: owner, peer: peer, admin: admin, outsider: outsider,
		upload:   uploadID,
		resolver: authz.New(testStore, slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("fixture setup: %v", err)
	}
}

func (f *fixture) grant(t *testing.T, subject *store.User, level string, uploadID *uuid.UUID, expires *time.Time) {
	t.Helper()
	_, err := testStore.UpsertGrant(context.Background(), store.AccessGrant{
		OrgID: f.org, UploadID: uploadID, SubjectUserID: subject.ID,
		Level: level, GrantedBy: f.owner.ID, ExpiresAt: expires,
	})
	must(t, err)
}

// TestResolveMatrix is the table the plan calls for: who gets what, before any
// requirement is applied.
func TestResolveMatrix(t *testing.T) {
	tests := []struct {
		name    string
		subject func(f *fixture) *store.User
		setup   func(t *testing.T, f *fixture)
		want    authz.Level
		wantErr error
	}{
		{
			name:    "owner gets full on their own upload",
			subject: func(f *fixture) *store.User { return f.owner },
			want:    authz.LevelFull,
		},
		{
			name:    "same-org member with no grant cannot see it exists",
			subject: func(f *fixture) *store.User { return f.peer },
			wantErr: authz.ErrNotFound,
		},
		{
			name:    "admin gets dashboard by default, not full",
			subject: func(f *fixture) *store.User { return f.admin },
			want:    authz.LevelDashboard,
		},
		{
			name:    "other org sees nothing",
			subject: func(f *fixture) *store.User { return f.outsider },
			wantErr: authz.ErrNotFound,
		},
		{
			name:    "per-upload summary grant",
			subject: func(f *fixture) *store.User { return f.peer },
			setup:   func(t *testing.T, f *fixture) { f.grant(t, f.peer, "summary", &f.upload, nil) },
			want:    authz.LevelSummary,
		},
		{
			name:    "per-upload dashboard grant",
			subject: func(f *fixture) *store.User { return f.peer },
			setup:   func(t *testing.T, f *fixture) { f.grant(t, f.peer, "dashboard", &f.upload, nil) },
			want:    authz.LevelDashboard,
		},
		{
			name:    "per-upload full grant",
			subject: func(f *fixture) *store.User { return f.peer },
			setup:   func(t *testing.T, f *fixture) { f.grant(t, f.peer, "full", &f.upload, nil) },
			want:    authz.LevelFull,
		},
		{
			name:    "org-wide grant applies to an upload the subject does not own",
			subject: func(f *fixture) *store.User { return f.peer },
			setup:   func(t *testing.T, f *fixture) { f.grant(t, f.peer, "dashboard", nil, nil) },
			want:    authz.LevelDashboard,
		},
		{
			name:    "expired grant is inert",
			subject: func(f *fixture) *store.User { return f.peer },
			setup: func(t *testing.T, f *fixture) {
				past := time.Now().Add(-time.Hour)
				f.grant(t, f.peer, "full", &f.upload, &past)
			},
			wantErr: authz.ErrNotFound,
		},
		{
			name:    "a grant never lowers an admin below dashboard",
			subject: func(f *fixture) *store.User { return f.admin },
			setup:   func(t *testing.T, f *fixture) { f.grant(t, f.admin, "summary", &f.upload, nil) },
			want:    authz.LevelDashboard,
		},
		{
			name:    "a full grant raises an admin above the default",
			subject: func(f *fixture) *store.User { return f.admin },
			setup:   func(t *testing.T, f *fixture) { f.grant(t, f.admin, "full", &f.upload, nil) },
			want:    authz.LevelFull,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			got, _, err := f.resolver.Resolve(context.Background(), tc.subject(f), f.upload)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Fatalf("want error %v, got level=%v err=%v", tc.wantErr, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

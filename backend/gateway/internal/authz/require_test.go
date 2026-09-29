package authz_test

import (
	"context"
	"testing"

	"github.com/logmonitor/gateway/internal/authz"
	"github.com/logmonitor/gateway/internal/store"
)

// TestRequireDistinguishesNotFoundFromForbidden pins the disclosure rule:
// no access at all reads as 404 (you may not learn the upload exists), while
// insufficient access reads as 403 (you know it exists, you just cannot go
// deeper). Collapsing these into one status would either leak existence or
// make a legitimate "ask for more access" indistinguishable from a typo.
func TestRequireDistinguishesNotFoundFromForbidden(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	if _, _, err := f.resolver.Require(ctx, f.peer, f.upload, authz.LevelSummary); err != authz.ErrNotFound {
		t.Fatalf("no grant at all should be ErrNotFound, got %v", err)
	}

	f.grant(t, f.peer, "summary", &f.upload, nil)

	if _, _, err := f.resolver.Require(ctx, f.peer, f.upload, authz.LevelSummary); err != nil {
		t.Fatalf("summary grant should satisfy a summary requirement: %v", err)
	}
	if _, _, err := f.resolver.Require(ctx, f.peer, f.upload, authz.LevelFull); err != authz.ErrForbidden {
		t.Fatalf("summary grant should not satisfy a full requirement, got %v", err)
	}
}

// TestMemberIsNeverEscalated: break-glass is an administrative power. A plain
// member who falls short is refused, full stop.
func TestMemberIsNeverEscalated(t *testing.T) {
	f := newFixture(t)
	f.grant(t, f.peer, "dashboard", &f.upload, nil)

	_, _, err := f.resolver.Require(context.Background(), f.peer, f.upload, authz.LevelFull)
	if err != authz.ErrForbidden {
		t.Fatalf("member should be refused, got %v", err)
	}
	if n := auditCount(t, f, "breakglass.raw_access"); n != 0 {
		t.Fatalf("a refused member must not produce a break-glass record, got %d", n)
	}
}

// TestAdminBreakGlassIsAllowedAndAudited is the whole justification for letting
// an admin read raw log lines they were not granted: it is allowed, and it
// leaves a record. Without the record this would just be surveillance.
func TestAdminBreakGlassIsAllowedAndAudited(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	level, _, err := f.resolver.Require(ctx, f.admin, f.upload, authz.LevelFull)
	if err != nil {
		t.Fatalf("admin break-glass should be permitted: %v", err)
	}
	if level != authz.LevelFull {
		t.Fatalf("break-glass should yield the required level, got %v", level)
	}
	if n := auditCount(t, f, "breakglass.raw_access"); n != 1 {
		t.Fatalf("want exactly one audit record, got %d", n)
	}
}

// TestNoBreakGlassRecordWhenAccessWasAlreadySufficient guards against audit
// noise: an admin reading a dashboard they are entitled to has not broken any
// glass, and logging it as though they had would train people to ignore the
// records that matter.
func TestNoBreakGlassRecordWhenAccessWasAlreadySufficient(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	if _, _, err := f.resolver.Require(ctx, f.admin, f.upload, authz.LevelDashboard); err != nil {
		t.Fatalf("admin should hold dashboard by default: %v", err)
	}
	if n := auditCount(t, f, "breakglass.raw_access"); n != 0 {
		t.Fatalf("want no audit record, got %d", n)
	}

	if _, _, err := f.resolver.Require(ctx, f.owner, f.upload, authz.LevelFull); err != nil {
		t.Fatalf("owner should hold full on their own upload: %v", err)
	}
	if n := auditCount(t, f, "breakglass.raw_access"); n != 0 {
		t.Fatalf("an owner reading their own file is not break-glass, got %d records", n)
	}
}

// TestCrossOrgIsNotFoundEvenForAnAdmin: admin reach stops at the organization
// boundary. An admin of one tenant is a stranger to another.
func TestCrossOrgIsNotFoundEvenForAnAdmin(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	outsiderAdmin := f.outsider // owner of the other org, so IsAdmin() is true
	if !outsiderAdmin.Role.IsAdmin() {
		t.Fatal("fixture assumption broken: outsider should be an org owner")
	}

	if _, _, err := f.resolver.Require(ctx, outsiderAdmin, f.upload, authz.LevelSummary); err != authz.ErrNotFound {
		t.Fatalf("cross-org admin must get ErrNotFound, got %v", err)
	}
	if n := auditCount(t, f, "breakglass.raw_access"); n != 0 {
		t.Fatalf("cross-org denial must not be recorded as break-glass, got %d", n)
	}
}

// TestListVisibleUploadsAgreesWithResolve: the list endpoint and the per-upload
// resolver must not drift. If a row is listed it must resolve, and if it
// resolves it must be listed -- otherwise the UI shows files that 404.
func TestListVisibleUploadsAgreesWithResolve(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		user    *store.User
		visible bool
	}{
		{"owner", f.owner, true},
		{"admin", f.admin, true},
		{"ungranted peer", f.peer, false},
		{"outsider", f.outsider, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ups, err := testStore.ListVisibleUploads(ctx, tc.user)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			listed := false
			for _, u := range ups {
				if u.ID == f.upload {
					listed = true
				}
			}
			_, _, resolveErr := f.resolver.Resolve(ctx, tc.user, f.upload)
			resolvable := resolveErr == nil

			if listed != tc.visible {
				t.Errorf("listed=%v, want %v", listed, tc.visible)
			}
			if listed != resolvable {
				t.Errorf("list says %v but resolve says %v -- they have drifted", listed, resolvable)
			}
		})
	}
}

func auditCount(t *testing.T, f *fixture, action string) int {
	t.Helper()
	var n int
	err := testStore.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = $2`, f.org, action).Scan(&n)
	if err != nil {
		t.Fatalf("audit count: %v", err)
	}
	return n
}

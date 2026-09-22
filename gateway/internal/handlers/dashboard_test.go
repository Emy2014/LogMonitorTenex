package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
)

// The dashboard endpoints are new query surface over tenant data, so the
// first thing worth testing is that they cannot be pointed at someone else's.

func TestDashboardDefaultsToOwnDataOnly(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	rec := c.do("GET", "/api/dashboard/summary", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Scope   string `json:"scope"`
		Summary struct {
			Empty bool `json:"empty"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Scope != "self" {
		t.Fatalf("default scope must be the caller's own data, got %q", out.Scope)
	}
	// Nothing has been ingested, so this must report empty rather than error.
	if !out.Summary.Empty {
		t.Error("with no data the summary should report empty")
	}
}

// A member asking for org-wide figures is refused outright rather than
// silently narrowed, so a UI bug surfaces instead of quietly showing the
// wrong thing.
func TestMemberCannotRequestOrgScope(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)

	memberEmail := uniqueEmail()
	owner.do("POST", "/api/org/invite", map[string]string{
		"email": memberEmail, "password": "supersecret2", "role": "member",
	})

	member := newClient(t, h)
	member.do("POST", "/api/auth/login", map[string]string{
		"email": memberEmail, "password": "supersecret2",
	})

	for _, path := range []string{
		"/api/dashboard/summary?scope=org",
		"/api/dashboard/series?scope=org",
		"/api/dashboard/top?scope=org",
	} {
		if rec := member.do("GET", path, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s: want 403 for a member, got %d", path, rec.Code)
		}
	}
}

func TestAdminMayRequestOrgScope(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)

	rec := owner.do("GET", "/api/dashboard/summary?scope=org", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner is an admin and should be allowed: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Scope string `json:"scope"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Scope != "org" {
		t.Fatalf("want org scope, got %q", out.Scope)
	}
}

func TestTopRejectsUnknownDimension(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	// The dimension reaches SQL as an identifier, so it is resolved through an
	// allowlist rather than interpolated. Anything else must be refused.
	for _, d := range []string{
		"password_hash",
		"1;DROP TABLE users",
		"totp_secret",
		"host); DELETE FROM users --",
	} {
		path := "/api/dashboard/top?dimension=" + url.QueryEscape(d)
		if rec := c.do("GET", path, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("dimension %q: want 400, got %d", d, rec.Code)
		}
	}

	// The allowlist is the control, so prove it still admits what it should.
	for _, d := range []string{"host", "url", "user", "ip", "category"} {
		if rec := c.do("GET", "/api/dashboard/top?dimension="+d, nil); rec.Code != http.StatusOK {
			t.Errorf("dimension %q should be allowed, got %d", d, rec.Code)
		}
	}
}

func TestSeriesReturnsEmptyArrayNotNull(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	rec := c.do("GET", "/api/dashboard/series?grain=hour", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	// A null would make the client's .map() throw; an empty array renders an
	// empty state. The difference matters because every panel starts here.
	var out struct {
		Points []any `json:"points"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Points == nil {
		t.Fatal("points must be [] rather than null when there is no data")
	}
}

func TestAuditLogIsAdminOnly(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)

	memberEmail := uniqueEmail()
	owner.do("POST", "/api/org/invite", map[string]string{
		"email": memberEmail, "password": "supersecret2", "role": "member",
	})
	member := newClient(t, h)
	member.do("POST", "/api/auth/login", map[string]string{
		"email": memberEmail, "password": "supersecret2",
	})

	if rec := member.do("GET", "/api/audit", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a member must not read the audit log, got %d", rec.Code)
	}
	if rec := owner.do("GET", "/api/audit", nil); rec.Code != http.StatusOK {
		t.Fatalf("an admin should read it, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestMeCarriesShellContext(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	rec := c.do("GET", "/api/auth/me", nil)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	for _, k := range []string{"email", "role", "org_id", "org_name", "mfa_enabled", "org_require_mfa"} {
		if _, ok := out[k]; !ok {
			t.Errorf("/me is missing %q, which the app shell needs", k)
		}
	}
}

// The bundled sample is dated March 2024. Every bounded window therefore
// returns nothing, and a dashboard that only offers bounded windows shows a
// wall of empty charts over a log the user just uploaded. The summary reports
// the span the data actually covers so the UI can widen instead.
func TestSummaryReportsTheDataSpanRegardlessOfWindow(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	me := c.do("GET", "/api/auth/me", nil)
	var u struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	_ = json.Unmarshal(me.Body.Bytes(), &u)
	seedEntriesFor(t, uuid.MustParse(u.OrgID), uuid.MustParse(u.ID), 50)

	// A 24-hour window over data from 2024 finds no requests...
	rec := c.do("GET", "/api/dashboard/summary", nil)
	var out struct {
		Summary struct {
			Requests  int64   `json:"requests"`
			Uploads   int64   `json:"uploads"`
			Empty     bool    `json:"empty"`
			DataStart *string `json:"data_start"`
			DataEnd   *string `json:"data_end"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	if out.Summary.Requests != 0 {
		t.Fatalf("precondition: the seeded data is from 2024, so a recent window should be empty; got %d", out.Summary.Requests)
	}
	// ...but the span must still be reported, or the UI cannot tell "nothing
	// ingested" from "nothing in this window".
	if out.Summary.DataStart == nil || out.Summary.DataEnd == nil {
		t.Fatal("data span must be reported even when the window is empty")
	}
	if out.Summary.Uploads == 0 {
		t.Error("uploads should be counted so the UI can distinguish the two cases")
	}
}

func TestDataSpanIsNilWhenNothingIngested(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	rec := c.do("GET", "/api/dashboard/summary", nil)
	var out struct {
		Summary struct {
			Empty     bool    `json:"empty"`
			DataStart *string `json:"data_start"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	if !out.Summary.Empty {
		t.Error("a fresh account should report empty")
	}
	if out.Summary.DataStart != nil {
		t.Errorf("no data means no span, got %v", *out.Summary.DataStart)
	}
}

// The span query drops the time predicate but must keep the tenancy one.
func TestDataSpanDoesNotLeakAcrossTenants(t *testing.T) {
	_, h := newAPI(t)

	victim, _ := registerUser(t, h)
	me := victim.do("GET", "/api/auth/me", nil)
	var v struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	_ = json.Unmarshal(me.Body.Bytes(), &v)
	seedEntriesFor(t, uuid.MustParse(v.OrgID), uuid.MustParse(v.ID), 30)

	outsider, _ := registerUser(t, h)
	rec := outsider.do("GET", "/api/dashboard/summary", nil)
	var out struct {
		Summary struct {
			DataStart *string `json:"data_start"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	if out.Summary.DataStart != nil {
		t.Fatalf("another tenant's data span is visible: %v", *out.Summary.DataStart)
	}
}

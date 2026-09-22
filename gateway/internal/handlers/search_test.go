package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
)

// seedFinding writes one analysis and one anomaly for a user, so search has
// something to find.
func seedFinding(t *testing.T, orgID, userID uuid.UUID, kind, explanation string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	uploadID := seedEntriesFor(t, orgID, userID, 10)

	var analysisID uuid.UUID
	if err := st.Pool.QueryRow(ctx, `
		INSERT INTO analyses (org_id, upload_id, status, scope)
		VALUES ($1, $2, 'done', 'file') RETURNING id`,
		orgID, uploadID).Scan(&analysisID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO anomalies (analysis_id, kind, severity, urgency, confidence,
		                       explanation, recommendation, entry_ids)
		VALUES ($1, $2, 'high', 'today', 0.9, $3, 'Block the destination', '{}')`,
		analysisID, kind, explanation); err != nil {
		t.Fatal(err)
	}
	return analysisID
}

func searchAs(t *testing.T, c *client, q string) (string, []map[string]any, bool) {
	t.Helper()
	rec := c.do("GET", "/api/search?q="+url.QueryEscape(q), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("search: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Mode              string           `json:"mode"`
		Hits              []map[string]any `json:"hits"`
		SemanticAvailable bool             `json:"semantic_available"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Mode, out.Hits, out.SemanticAvailable
}

func meIDs(t *testing.T, c *client) (uuid.UUID, uuid.UUID) {
	t.Helper()
	rec := c.do("GET", "/api/auth/me", nil)
	var u struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &u)
	return uuid.MustParse(u.OrgID), uuid.MustParse(u.ID)
}

// Search works with no embedding provider configured. This is the point of
// the text backend: a tool whose search is dark until someone buys an API key
// has no search.
func TestSearchWorksWithoutAnEmbeddingProvider(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)
	orgID, userID := meIDs(t, c)
	seedFinding(t, orgID, userID, "data_exfil",
		"Large outbound transfer to files.dropzone-sync.ru over twelve chunks")

	mode, hits, semantic := searchAs(t, c, "outbound transfer")
	if mode != "text" {
		t.Errorf("mode = %q, want text", mode)
	}
	if semantic {
		t.Error("semantic should report unavailable with no vectors stored")
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0]["kind"] != "data_exfil" {
		t.Errorf("wrong hit: %v", hits[0])
	}
}

// The predicate that matters: search must never reach another tenant.
func TestSearchNeverCrossesOrganizations(t *testing.T) {
	_, h := newAPI(t)

	victim, _ := registerUser(t, h)
	vOrg, vUser := meIDs(t, victim)
	seedFinding(t, vOrg, vUser, "beaconing",
		"Periodic check-in to cdn-telemetry-sync.net every sixty seconds")

	outsider, _ := registerUser(t, h)
	if _, hits, _ := searchAs(t, outsider, "cdn-telemetry-sync"); len(hits) != 0 {
		t.Fatalf("cross-tenant leak: outsider found %d findings", len(hits))
	}
	if _, hits, _ := searchAs(t, victim, "cdn-telemetry-sync"); len(hits) != 1 {
		t.Fatalf("owner should find their own finding, got %d", len(hits))
	}
}

// A colleague with no grant sees nothing; the same query works once granted.
func TestSearchRespectsGrants(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, ownerID := meIDs(t, owner)
	seedFinding(t, orgID, ownerID, "rare_destination",
		"Rarely-seen destination paste-anon-share.onion.ly visited once")

	peerEmail := uniqueEmail()
	rec := owner.do("POST", "/api/org/invite", map[string]string{
		"email": peerEmail, "password": "supersecret2", "role": "member"})
	var peerUser struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &peerUser)

	peer := newClient(t, h)
	peer.do("POST", "/api/auth/login", map[string]string{
		"email": peerEmail, "password": "supersecret2"})

	if _, hits, _ := searchAs(t, peer, "paste-anon-share"); len(hits) != 0 {
		t.Fatalf("ungranted member found %d findings", len(hits))
	}

	owner.do("POST", "/api/grants", map[string]any{
		"subject_user_id": peerUser.ID, "level": "summary"})

	if _, hits, _ := searchAs(t, peer, "paste-anon-share"); len(hits) != 1 {
		t.Fatalf("granted member should find it, got %d", len(hits))
	}
}

// An admin sees org-wide findings without needing an explicit grant, matching
// the default reach the authz resolver gives them.
func TestAdminSearchesOrgWide(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, ownerID := meIDs(t, owner)
	seedFinding(t, orgID, ownerID, "volume_spike",
		"Request burst from 10.12.4.102 across three minutes")

	if _, hits, _ := searchAs(t, owner, "request burst"); len(hits) != 1 {
		t.Fatalf("admin should see org findings, got %d", len(hits))
	}
}

func TestSearchRejectsEmptyAndOversizedQueries(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	if rec := c.do("GET", "/api/search?q=", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("empty query: want 400, got %d", rec.Code)
	}
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	if rec := c.do("GET", "/api/search?q="+string(long), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized query: want 400, got %d", rec.Code)
	}
}

// websearch_to_tsquery parses user input as a search expression, so quotes and
// operators are input, never syntax errors.
func TestSearchToleratesQueryOperators(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)
	orgID, userID := meIDs(t, c)
	seedFinding(t, orgID, userID, "off_hours", "Off-hours activity by d.kim at 03:00")

	for _, q := range []string{`"off hours"`, "off OR hours", "off -hours", "!!!", "a & b | c"} {
		if rec := c.do("GET", "/api/search?q="+url.QueryEscape(q), nil); rec.Code != http.StatusOK {
			t.Errorf("query %q returned %d, want 200", q, rec.Code)
		}
	}
}

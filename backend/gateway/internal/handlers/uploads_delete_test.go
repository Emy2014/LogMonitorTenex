package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// entryCount is the check that matters most here: log_entries is the one table
// with no foreign key to uploads, so it is the one that would silently survive
// a delete that looked successful from the outside.
func entryCount(t *testing.T, uploadID uuid.UUID) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM log_entries WHERE upload_id = $1`, uploadID).Scan(&n); err != nil {
		t.Fatalf("count entries: %v", err)
	}
	return n
}

func auditCount(t *testing.T, orgID uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = $2`,
		orgID, action).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// inviteMember creates a second user in the caller's org and returns a logged
// in client for them plus their id.
func inviteMember(t *testing.T, h http.Handler, owner *client, role string) (*client, uuid.UUID) {
	t.Helper()
	email := uniqueEmail()
	rec := owner.do("POST", "/api/org/invite", map[string]string{
		"email": email, "password": "supersecret2", "role": role})
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("invite %s: %d %s", role, rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	c := newClient(t, h)
	if rec := c.do("POST", "/api/auth/login", map[string]string{
		"email": email, "password": "supersecret2"}); rec.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", role, rec.Code, rec.Body.String())
	}
	return c, uuid.MustParse(created.ID)
}

func TestOwnerDeletesOwnUploadAndItsEntries(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, ownerID := meIDs(t, owner)
	uploadID := seedEntriesFor(t, orgID, ownerID, 20)

	if got := entryCount(t, uploadID); got == 0 {
		t.Fatal("seed wrote no entries, the test would pass vacuously")
	}

	if rec := owner.do("DELETE", "/api/uploads/"+uploadID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if got := entryCount(t, uploadID); got != 0 {
		t.Errorf("log_entries survived the delete: %d rows still present", got)
	}

	rec := owner.do("GET", "/api/uploads", nil)
	var list []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	for _, u := range list {
		if u.ID == uploadID.String() {
			t.Error("deleted upload is still listed")
		}
	}
}

// Deleting is recorded. The audit row is the whole justification for letting
// an admin destroy someone else's data, so its absence is a failure.
func TestAdminDeleteIsAudited(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, _ := meIDs(t, owner)

	member, memberID := inviteMember(t, h, owner, "member")
	uploadID := seedEntriesFor(t, orgID, memberID, 10)

	before := auditCount(t, orgID, "upload.deleted")
	if rec := owner.do("DELETE", "/api/uploads/"+uploadID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("admin delete: %d %s", rec.Code, rec.Body.String())
	}
	if after := auditCount(t, orgID, "upload.deleted"); after != before+1 {
		t.Errorf("audit rows: got %d, want %d", after, before+1)
	}
	// The member's own view agrees it is gone.
	rec := member.do("GET", "/api/uploads", nil)
	if body := rec.Body.String(); strings.Contains(body, uploadID.String()) {
		t.Error("owner of the deleted upload can still see it")
	}
}

func TestMemberCannotDeleteAnotherUsersUpload(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, ownerID := meIDs(t, owner)
	uploadID := seedEntriesFor(t, orgID, ownerID, 10)

	member, _ := inviteMember(t, h, owner, "member")
	if rec := member.do("DELETE", "/api/uploads/"+uploadID.String(), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for a non-owner member, got %d %s", rec.Code, rec.Body.String())
	}
	if got := entryCount(t, uploadID); got == 0 {
		t.Error("a refused delete removed the entries anyway")
	}
}

// A grant shares a view. It is not a licence to destroy what was shared, and
// that holds at 'full', the level that grants everything a read can ask for.
func TestFullGrantDoesNotConferDelete(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, ownerID := meIDs(t, owner)
	uploadID := seedEntriesFor(t, orgID, ownerID, 10)

	peer, peerID := inviteMember(t, h, owner, "member")
	if rec := owner.do("POST", "/api/grants", map[string]any{
		"subject_user_id": peerID.String(),
		"upload_id":       uploadID.String(),
		"level":           "full",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("grant: %d %s", rec.Code, rec.Body.String())
	}

	if rec := peer.do("DELETE", "/api/uploads/"+uploadID.String(), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for a full-grant holder, got %d %s", rec.Code, rec.Body.String())
	}
	if got := entryCount(t, uploadID); got == 0 {
		t.Error("a refused delete removed the entries anyway")
	}
}

// Cross-org must be 404, not 403: a 403 would confirm the id is real, which is
// the same disclosure the read path takes care to avoid.
func TestCrossOrgDeleteIsNotFoundNotForbidden(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, ownerID := meIDs(t, owner)
	uploadID := seedEntriesFor(t, orgID, ownerID, 10)

	stranger, _ := registerUser(t, h) // their own org
	if rec := stranger.do("DELETE", "/api/uploads/"+uploadID.String(), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 across orgs, got %d %s", rec.Code, rec.Body.String())
	}
	if got := entryCount(t, uploadID); got == 0 {
		t.Error("a cross-org delete removed the entries")
	}
}

// A second delete is not an error state worth a 500; the caller asked for the
// upload to be gone and it is.
func TestDeletingTwiceIsNotFound(t *testing.T) {
	_, h := newAPI(t)
	owner, _ := registerUser(t, h)
	orgID, ownerID := meIDs(t, owner)
	uploadID := seedEntriesFor(t, orgID, ownerID, 5)

	if rec := owner.do("DELETE", "/api/uploads/"+uploadID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("first delete: %d", rec.Code)
	}
	if rec := owner.do("DELETE", "/api/uploads/"+uploadID.String(), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete: want 404, got %d", rec.Code)
	}
}

package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/parser"
	"github.com/logmonitor/gateway/internal/store"

	_ "github.com/logmonitor/gateway/internal/parser/zscaler"
)

func storeBatch(uploadID, orgID, userID uuid.UUID) store.IngestBatch {
	return store.IngestBatch{UploadID: uploadID, OrgID: orgID, UserID: userID}
}

// seedEntries creates an org, a user and an ingested upload, exercising the
// real parse -> COPY -> rollup path minus object storage.
func seedEntries(t *testing.T, n int) (orgID, userID, uploadID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	_, owner, err := testStoreCreateOrg(ctx, "Seed "+suffix, "seed-"+suffix, "seed-"+suffix+"@t.io")
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return owner.OrgID, owner.ID, seedEntriesFor(t, owner.OrgID, owner.ID, n)
}

func testStoreCreateOrg(ctx context.Context, name, slug, email string) (*store.Organization, *store.User, error) {
	return st.CreateOrgWithOwner(ctx, name, slug, email, "x")
}

// seedEntriesFor ingests n synthetic rows for an existing user, plus one row
// that cannot be parsed, so the "unparseable rows are kept" rule is covered.
func seedEntriesFor(t *testing.T, orgID, userID uuid.UUID, n int) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	body := sampleLog(n) + "this-line-is-not-valid\n"
	p := parser.ByKey("zscaler_nss")
	if p == nil {
		t.Fatal("zscaler parser is not registered")
	}

	tx, err := st.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	uploadID := uuid.New()
	batch := storeBatch(uploadID, orgID, userID)

	var entries []parser.Entry
	stats, err := p.Parse(strings.NewReader(body), func(e parser.Entry) error {
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var minTS, maxTS *time.Time
	for _, e := range entries {
		if e.TS == nil {
			continue
		}
		if minTS == nil || e.TS.Before(*minTS) {
			v := *e.TS
			minTS = &v
		}
		if maxTS == nil || e.TS.After(*maxTS) {
			v := *e.TS
			maxTS = &v
		}
	}
	if err := st.EnsurePartitions(ctx, tx, minTS, maxTS); err != nil {
		t.Fatalf("partitions: %v", err)
	}
	if _, err := st.CopyEntries(ctx, tx, batch, entries); err != nil {
		t.Fatalf("copy: %v", err)
	}
	up := &store.Upload{
		ID: uploadID, OrgID: orgID, UserID: userID, Filename: "seed.log",
		ByteSize: int64(len(body)), LineCount: stats.LineCount,
		ParsedCount: stats.ParsedCount, Format: p.Key(), ObjectKey: "seed",
	}
	if err := st.CreateUpload(ctx, tx, up); err != nil {
		t.Fatalf("upload row: %v", err)
	}
	if err := st.BuildRollups(ctx, tx, batch); err != nil {
		t.Fatalf("rollups: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	t.Cleanup(func() {
		_, _ = st.Pool.Exec(context.Background(), `DELETE FROM uploads WHERE id = $1`, uploadID)
	})
	return uploadID
}

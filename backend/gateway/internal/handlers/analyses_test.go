package handlers

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/logmonitor/gateway/internal/queue"
	"github.com/logmonitor/gateway/internal/store"
)

func TestNormaliseScope(t *testing.T) {
	seven, big := 7, 400
	cases := []struct {
		name       string
		scope      string
		window     *int
		wantScope  string
		wantWindow int // 0 means nil
		wantErr    bool
	}{
		{"empty defaults to file", "", nil, "file", 0, false},
		{"file ignores a window", "file", &seven, "file", 0, false},
		{"unknown is file", "bogus", &seven, "file", 0, false},
		{"history defaults its window", "history", nil, "history", 30, false},
		{"history keeps its window", "history", &seven, "history", 7, false},
		{"history caps the window", "history", &big, "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope, window, err := normaliseScope(c.scope, c.window)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err != nil {
				return
			}
			if scope != c.wantScope {
				t.Errorf("scope = %q, want %q", scope, c.wantScope)
			}
			got := 0
			if window != nil {
				got = *window
			}
			if got != c.wantWindow {
				t.Errorf("window = %d, want %d", got, c.wantWindow)
			}
		})
	}
}

// Ingest launches the analysis itself -- an upload nobody analyses is just
// storage -- and the explicit route re-runs one. Both go through
// launchAnalysis, so this pins what a launch leaves behind: a queued row that
// is the upload's latest analysis, covering every entry.
func TestLaunchAnalysisQueuesTheUpload(t *testing.T) {
	ctx := context.Background()
	_, _, uploadID := seedEntries(t, 60)

	api, _ := newAPI(t)
	pub, err := queue.New(os.Getenv("TEST_REDIS_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	api.Queue = pub
	api.Cfg.ShardSize = 25

	upload, err := st.UploadByID(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}

	// Every non-header line is an entry, the unparseable one included.
	entries := upload.LineCount - 1

	analysis, shards, err := api.launchAnalysis(ctx, upload, "file", nil, entries)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if analysis.Status != "queued" {
		t.Errorf("status = %q, want queued", analysis.Status)
	}
	if analysis.Scope != "file" || analysis.BaselineWindowDays != nil {
		t.Errorf("scope = %q window = %v, want file/nil", analysis.Scope, analysis.BaselineWindowDays)
	}
	if shards < 1 {
		t.Errorf("shards = %d, want at least one", shards)
	}
	// What ingest passes is what the database holds, or the shard fan-out
	// would cover the wrong number of rows.
	counted, err := st.CountEntries(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if counted != entries {
		t.Errorf("CountEntries = %d, but the analysis was sized for %d", counted, entries)
	}

	latest, err := st.LatestAnalysisFor(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != analysis.ID {
		t.Errorf("latest analysis = %s, want %s", latest.ID, analysis.ID)
	}
}

// Without a queue nothing could consume the job, so no row may be created:
// a queued analysis with no job behind it would sit at "queued" for ever.
func TestLaunchAnalysisWithoutQueueCreatesNoRow(t *testing.T) {
	ctx := context.Background()
	_, _, uploadID := seedEntries(t, 10)
	api, _ := newAPI(t) // newAPI wires no queue

	upload, err := st.UploadByID(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := api.launchAnalysis(ctx, upload, "file", nil, 10); !errors.Is(err, errNoQueue) {
		t.Fatalf("err = %v, want errNoQueue", err)
	}
	if _, err := st.LatestAnalysisFor(ctx, uploadID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected no analysis row, got err = %v", err)
	}
}

// The list carries each upload's latest analysis so the page can show its
// state without a request per row.
func TestUploadListCarriesLatestAnalysis(t *testing.T) {
	ctx := context.Background()
	orgID, userID, uploadID := seedEntries(t, 10)

	caller, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}

	items, err := st.ListVisibleUploads(ctx, caller)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != uploadID {
		t.Fatalf("items = %+v, want just %s", items, uploadID)
	}
	if items[0].AnalysisID != nil || items[0].AnalysisStatus != nil {
		t.Errorf("fresh upload should carry no analysis, got %+v", items[0])
	}

	first, err := st.CreateAnalysis(ctx, orgID, uploadID, "file", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.CreateAnalysis(ctx, orgID, uploadID, "file", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = first

	items, err = st.ListVisibleUploads(ctx, caller)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].AnalysisID == nil || *items[0].AnalysisID != second.ID {
		t.Errorf("analysis_id = %v, want the most recent %s", items[0].AnalysisID, second.ID)
	}
	if items[0].AnalysisStatus == nil || *items[0].AnalysisStatus != "queued" {
		t.Errorf("analysis_status = %v, want queued", items[0].AnalysisStatus)
	}
}

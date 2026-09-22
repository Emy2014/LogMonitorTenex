package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/authz"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/queue"
	"github.com/logmonitor/gateway/internal/store"
)

type analyzeRequest struct {
	Scope              string `json:"scope"` // file | history
	BaselineWindowDays *int   `json:"baseline_window_days"`
}

// errNoQueue: the gateway came up without Redis, so a job would have no
// consumer. Callers turn it into a 503 rather than a queued-forever row.
var errNoQueue = errors.New("the analysis queue is unavailable; no worker can pick this up")

// normaliseScope applies the rules both entry points share. Anything other
// than "history" is a file-scoped analysis with no window; history defaults
// its window rather than letting the schema's CHECK reject the insert.
func normaliseScope(scope string, window *int) (string, *int, error) {
	if scope != "history" {
		return "file", nil, nil
	}
	if window == nil || *window <= 0 {
		d := 30
		window = &d
	}
	if *window > 365 {
		return "", nil, errors.New("baseline_window_days cannot exceed 365")
	}
	return "history", window, nil
}

// launchAnalysis creates the analysis row and fans it out to the workers.
//
// Shared by ingest, which launches one as soon as a file lands, and the
// explicit analyze route, which re-runs one. entries is how many log rows the
// upload holds, which decides the shard count; the caller supplies it because
// ingest already knows it and only the re-run route has to ask the database.
// If the enqueue fails the row is marked failed on the way out, so nothing is
// ever left queued with no job behind it.
func (a *API) launchAnalysis(ctx context.Context, upload *store.Upload, scope string, window *int, entries int) (*store.Analysis, int, error) {
	if a.Queue == nil {
		return nil, 0, errNoQueue
	}

	analysis, err := a.Store.CreateAnalysis(ctx, upload.OrgID, upload.ID, scope, window)
	if err != nil {
		return nil, 0, fmt.Errorf("create analysis: %w", err)
	}

	shards, err := a.Queue.PublishAnalysis(ctx, queue.Job{
		AnalysisID:         analysis.ID.String(),
		UploadID:           upload.ID.String(),
		OrgID:              upload.OrgID.String(),
		UserID:             upload.UserID.String(),
		Scope:              scope,
		BaselineWindowDays: window,
	}, entries, a.Cfg.ShardSize)
	if err != nil {
		// The row exists but nothing will consume it, so say so rather than
		// leaving an analysis queued for ever.
		_ = a.Store.FailAnalysis(ctx, analysis.ID, "could not enqueue: "+err.Error())
		return nil, 0, fmt.Errorf("enqueue: %w", err)
	}

	a.Log.Info("analysis queued", "event", "analysis.queued",
		"analysis_id", analysis.ID, "upload_id", upload.ID,
		"entries", entries, "shards", shards, "scope", scope)
	return analysis, shards, nil
}

// startAnalysis queues an analysis and fans it out into shards.
//
// Ingest already does this for every upload; this route re-runs one, for an
// upload that predates automatic analysis or that should be scored against a
// different baseline.
//
// Requires full access, not dashboard: analysis reads every log line of the
// upload, so being able to see the charts is not enough to trigger one.
func (a *API) startAnalysis(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	uploadID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "id must be a uuid")
		return
	}
	_, upload, err := a.Authz.Require(r.Context(), caller, uploadID, authz.LevelFull)
	if err != nil {
		failAuthz(w, err)
		return
	}

	// Always attempt the decode, tolerating an empty body.
	//
	// Guarding on r.ContentLength > 0 looks reasonable and is wrong here: the
	// Next.js proxy strips Content-Length and forwards chunked, so Go reports
	// -1 and the guard silently skipped the body. The effect was that
	// scope=history was accepted, ignored, and recorded as scope=file --
	// a request that appeared to succeed while doing something else.
	var req analyzeRequest
	if err := httpx.DecodeOptional(w, r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}

	scope, window, err := normaliseScope(req.Scope, req.BaselineWindowDays)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}

	// No in-memory count on this path, unlike ingest: the rows were written by
	// an earlier request, so the database is the only place the number lives.
	entries, err := a.Store.CountEntries(r.Context(), uploadID)
	if err != nil {
		a.Log.Error("count entries failed", "event", "analysis.count_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not start the analysis")
		return
	}

	analysis, shards, err := a.launchAnalysis(r.Context(), upload, scope, window, entries)
	switch {
	case errors.Is(err, errNoQueue):
		httpx.Fail(w, http.StatusServiceUnavailable, err.Error())
		return
	case err != nil:
		a.Log.Error("start analysis failed", "event", "analysis.start_failed",
			"upload_id", uploadID, "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not start the analysis")
		return
	}

	httpx.JSON(w, http.StatusAccepted, map[string]any{
		"id": analysis.ID, "status": analysis.Status,
		"scope": scope, "shards": shards, "entries": entries,
	})
}

// getAnalysis returns one analysis with its findings.
//
// Summary tier is enough: the narrative and the findings are what a summary
// grant is for. The raw rows a finding points at still need full.
func (a *API) getAnalysis(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "id must be a uuid")
		return
	}

	analysis, err := a.Store.AnalysisByID(r.Context(), id)
	if err != nil {
		httpx.Fail(w, http.StatusNotFound, "Analysis not found")
		return
	}
	// Authorised through the parent upload, so one resolver governs both.
	level, _, err := a.Authz.Require(r.Context(), caller, analysis.UploadID, authz.LevelSummary)
	if err != nil {
		failAuthz(w, err)
		return
	}

	anomalies, err := a.Store.Anomalies(r.Context(), id)
	if err != nil {
		a.Log.Error("load anomalies failed", "event", "analysis.anomalies_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not load findings")
		return
	}

	// A summary-tier holder gets the finding but not the rows it cites.
	if level < authz.LevelFull {
		for i := range anomalies {
			anomalies[i].EntryIDs = nil
		}
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"analysis": analysis, "anomalies": anomalies, "level": level.String(),
	})
}

func failAuthz(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		httpx.Fail(w, http.StatusForbidden, "You do not have access to this")
	case errors.Is(err, authz.ErrNotFound):
		httpx.Fail(w, http.StatusNotFound, "Not found")
	default:
		httpx.Fail(w, http.StatusInternalServerError, "Something went wrong")
	}
}

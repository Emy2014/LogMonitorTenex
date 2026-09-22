package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const testHeader = "datetime,login,ClientIP,requestmethod,requestsize,responsesize," +
	"url,host,urlcategory,action,respcode,useragent,threatname,totaltime,cachehit"

func row(ts, user, ip, method string, req, resp int, host string, code int, latency int, cache string) string {
	return fmt.Sprintf("%s,%s,%s,%s,%d,%d,https://%s/a,%s,News,Allowed,%d,Mozilla/5.0,,%d,%s",
		ts, user, ip, method, req, resp, host, host, code, latency, cache)
}

// upload posts a multipart body the same way the browser does.
func (c *client) upload(filename, body string, fields map[string]string) *httptest.ResponseRecorder {
	c.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write([]byte(body))
	_ = mw.Close()

	req := httptest.NewRequest("POST", "/api/uploads", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Forwarded-For", c.ip)
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec
}

func sampleLog(n int) string {
	var b strings.Builder
	b.WriteString(testHeader + "\n")
	for i := 0; i < n; i++ {
		code := 200
		if i%10 == 0 {
			code = 404
		}
		cache := "TCP_MISS"
		if i%4 == 0 {
			cache = "TCP_HIT"
		}
		b.WriteString(row(
			fmt.Sprintf("2024-03-14 %02d:%02d:00", 8+i%4, i%60),
			fmt.Sprintf("user%d", i%3),
			fmt.Sprintf("10.0.0.%d", 1+i%5),
			"GET", 100+i, 1000+i,
			fmt.Sprintf("host%d.example.com", i%2),
			code, 10+i%50, cache) + "\n")
	}
	return b.String()
}

// Ingest needs object storage, which these tests do not stand up. Everything
// below therefore asserts on the pre-storage behaviour, which is where the
// interesting rules live; the full path is exercised against the real stack.
func TestUploadRejectsUnsupportedExtension(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	rec := c.upload("payload.exe", sampleLog(3), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for .exe, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Unsupported file type") {
		t.Errorf("message should say why: %s", rec.Body.String())
	}
}

func TestUploadRequiresAuthentication(t *testing.T) {
	_, h := newAPI(t)
	anon := newClient(t, h)

	if rec := anon.upload("a.log", sampleLog(1), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestUploadRejectsNonMultipart(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	req := httptest.NewRequest("POST", "/api/uploads", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// --- rollup arithmetic ------------------------------------------------------

// The dashboard reads rollups, the events table reads raw rows. If those two
// disagree the product contradicts itself, so the aggregation is checked
// against a direct GROUP BY over the same rows.
func TestRollupsMatchRawAggregates(t *testing.T) {
	ctx := context.Background()
	orgID, userID, uploadID := seedEntries(t, 240)

	// ts IS NOT NULL on both sides: a row whose timestamp could not be
	// recovered is kept in log_entries but belongs to no time bucket, which
	// TestUnparseableRowsStayOutOfRollups pins separately.
	var rawReq, rawErr, rawIn, rawOut, rawHits, rawCacheable int64
	err := st.Pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE resp_code >= 400),
		       COALESCE(SUM(resp_bytes),0), COALESCE(SUM(req_bytes),0),
		       COUNT(*) FILTER (WHERE upper(cache_status) LIKE '%HIT%'),
		       COUNT(*) FILTER (WHERE cache_status IS NOT NULL)
		  FROM log_entries
		 WHERE upload_id = $1
		   AND ts IS NOT NULL`, uploadID).
		Scan(&rawReq, &rawErr, &rawIn, &rawOut, &rawHits, &rawCacheable)
	if err != nil {
		t.Fatal(err)
	}

	for _, grain := range []string{"minute", "hour"} {
		var req, errs, in, out, hits, cacheable int64
		err := st.Pool.QueryRow(ctx, `
			SELECT COALESCE(SUM(requests),0), COALESCE(SUM(errors),0),
			       COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
			       COALESCE(SUM(cache_hits),0), COALESCE(SUM(cache_total),0)
			  FROM entry_rollups WHERE upload_id = $1 AND grain = $2::rollup_grain`,
			uploadID, grain).Scan(&req, &errs, &in, &out, &hits, &cacheable)
		if err != nil {
			t.Fatal(err)
		}
		if req != rawReq {
			t.Errorf("%s: requests %d, raw %d", grain, req, rawReq)
		}
		if errs != rawErr {
			t.Errorf("%s: errors %d, raw %d", grain, errs, rawErr)
		}
		if in != rawIn || out != rawOut {
			t.Errorf("%s: bytes %d/%d, raw %d/%d", grain, in, out, rawIn, rawOut)
		}
		if hits != rawHits || cacheable != rawCacheable {
			t.Errorf("%s: cache %d/%d, raw %d/%d", grain, hits, cacheable, rawHits, rawCacheable)
		}
	}
	_ = orgID
	_ = userID
}

// A rollup is per bucket, so re-running ingest for the same upload must
// overwrite rather than double every figure.
func TestRollupsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	_, _, uploadID := seedEntries(t, 60)

	var before int64
	_ = st.Pool.QueryRow(ctx,
		`SELECT SUM(requests) FROM entry_rollups WHERE upload_id=$1 AND grain='hour'`,
		uploadID).Scan(&before)

	tx, err := st.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var orgID, userID uuid.UUID
	_ = st.Pool.QueryRow(ctx, `SELECT org_id, user_id FROM uploads WHERE id=$1`, uploadID).
		Scan(&orgID, &userID)
	if err := st.BuildRollups(ctx, tx, storeBatch(uploadID, orgID, userID)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var after int64
	_ = st.Pool.QueryRow(ctx,
		`SELECT SUM(requests) FROM entry_rollups WHERE upload_id=$1 AND grain='hour'`,
		uploadID).Scan(&after)

	if before != after {
		t.Fatalf("re-running the rollup doubled the figures: %d then %d", before, after)
	}
}

// Rows whose timestamp could not be recovered still exist, and must not be
// silently counted into a time bucket they do not belong to.
func TestUnparseableRowsStayOutOfRollups(t *testing.T) {
	ctx := context.Background()
	_, _, uploadID := seedEntries(t, 20)

	var nullTS int64
	_ = st.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM log_entries WHERE upload_id=$1 AND ts IS NULL`, uploadID).Scan(&nullTS)
	if nullTS == 0 {
		t.Skip("fixture produced no unparseable rows")
	}

	var rolled, total int64
	_ = st.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(requests),0) FROM entry_rollups WHERE upload_id=$1 AND grain='hour'`,
		uploadID).Scan(&rolled)
	_ = st.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM log_entries WHERE upload_id=$1`, uploadID).Scan(&total)

	if rolled != total-nullTS {
		t.Fatalf("rolled %d of %d rows (%d have no timestamp)", rolled, total, nullTS)
	}
}

func TestDashboardReflectsIngestedRows(t *testing.T) {
	_, h := newAPI(t)
	c, _ := registerUser(t, h)

	me := c.do("GET", "/api/auth/me", nil)
	// Explicit tags: OrgID would never match "org_id" on field name alone.
	var u struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	_ = json.Unmarshal(me.Body.Bytes(), &u)
	seedEntriesFor(t, uuid.MustParse(u.OrgID), uuid.MustParse(u.ID), 120)

	rec := c.do("GET", "/api/dashboard/summary?from=2024-01-01T00:00:00Z", nil)
	var out struct {
		Summary struct {
			Requests int64 `json:"requests"`
			Empty    bool  `json:"empty"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	if out.Summary.Empty {
		t.Error("the summary should not report empty once rows exist")
	}
	if out.Summary.Requests != 120 {
		t.Errorf("requests = %d, want 120", out.Summary.Requests)
	}
}

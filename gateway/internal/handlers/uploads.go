package handlers

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/blob"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/parser"
	"github.com/logmonitor/gateway/internal/store"

	_ "github.com/logmonitor/gateway/internal/parser/zscaler" // register the parser
)

var allowedSuffixes = []string{".log", ".txt", ".csv", ".tsv"}

// errTooLarge is raised from inside the tee the moment the cap is passed, so
// the request is refused while the body is still arriving rather than after
// the whole thing has been read into memory.
var errTooLarge = errors.New("upload exceeds the size limit")

// capReader fails the read once total exceeds limit.
type capReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.limit {
		return n, errTooLarge
	}
	return n, err
}

// createUpload streams a log file into object storage and the database.
//
// The shape of this handler is the entire argument for Go owning ingest:
//
//	part ──┬─► cap check (as bytes arrive, not after buffering)
//	       ├─► zstd ──► object store        (raw bytes retained)
//	       └─► parser ──► COPY ──► rollups  (one transaction)
//
// v1 did `payload = await file.read()` and only then checked the size, so the
// 10MB limit existed mainly to stop that being fatal.
//
// Here nothing holds the file. Measured with GOMEMLIMIT set: the heap sits at
// 66 MB whether the upload is 1 MB or 400 MB, and 400 MB of NSS log (984k
// lines) ingests in ~22s. Without a memory limit Go simply keeps ~600 MB of
// GC headroom -- still independent of file size, just wasteful.
func (a *API) createUpload(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	mr, err := r.MultipartReader()
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "Expected a multipart upload")
		return
	}

	var (
		filename string
		scope    = "file"
		window   int
		result   *ingestResult
	)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			httpx.Fail(w, http.StatusBadRequest, "Malformed multipart body")
			return
		}

		switch part.FormName() {
		case "scope":
			scope = readSmallField(part)
		case "baseline_window_days":
			fmt.Sscanf(readSmallField(part), "%d", &window)
		case "file":
			filename = part.FileName()
			if filename == "" {
				filename = "upload.log"
			}
			if !hasAllowedSuffix(filename) {
				httpx.Fail(w, http.StatusBadRequest,
					"Unsupported file type. Expected one of: "+strings.Join(allowedSuffixes, ", "))
				return
			}
			// Checked here rather than at the top of the handler: a malformed
			// request should be told what is wrong with it, not handed a 503
			// about infrastructure it was never going to reach.
			if a.Blob == nil {
				httpx.Fail(w, http.StatusServiceUnavailable, "Object storage is not configured")
				return
			}
			result, err = a.ingest(r, caller, filename, part)
			if err != nil {
				a.failIngest(w, err)
				return
			}
		default:
			_, _ = io.Copy(io.Discard, part)
		}
		_ = part.Close()
	}

	if result == nil {
		httpx.Fail(w, http.StatusBadRequest, "No file part in the request")
		return
	}
	a.Log.Info("upload ingested",
		"event", "upload.ingested",
		"upload_id", result.upload.ID,
		"bytes", result.upload.ByteSize,
		"lines", result.upload.LineCount,
		"parsed", result.upload.ParsedCount,
		"unparsed", result.upload.LineCount-result.upload.ParsedCount,
		"format", result.upload.Format,
		"duration_ms", result.durationMS)

	resp := map[string]any{
		"id":           result.upload.ID,
		"filename":     result.upload.Filename,
		"line_count":   result.upload.LineCount,
		"parsed_count": result.upload.ParsedCount,
		"byte_size":    result.upload.ByteSize,
		"format":       result.upload.Format,
	}

	// An upload is only useful once analysed, and the scope was chosen on the
	// upload form, so launch the analysis here rather than wait for a second
	// request nothing in the UI makes. The file is already ingested by this
	// point, so a launch problem is reported alongside the upload rather than
	// failing it: the rows exist and the analysis can be re-run.
	//
	// COPY already counted the rows, so the analysis is sized from that rather
	// than from a count(*) over what we have only just written.
	scope, windowPtr, err := normaliseScope(scope, &window)
	var analysis *store.Analysis
	var shards int
	if err == nil {
		analysis, shards, err = a.launchAnalysis(
			r.Context(), result.upload, scope, windowPtr, int(result.entries))
	}
	resp["scope"] = scope

	if err != nil {
		a.Log.Error("analysis did not start after ingest",
			"event", "analysis.auto_start_failed",
			"upload_id", result.upload.ID, "err", err)
		resp["analysis"] = nil
		resp["analysis_error"] = "The file was ingested but its analysis could not be started: " + err.Error()
	} else {
		resp["analysis"] = map[string]any{
			"id": analysis.ID, "status": analysis.Status, "scope": scope, "shards": shards,
		}
	}

	httpx.JSON(w, http.StatusCreated, resp)
}

type ingestResult struct {
	upload *store.Upload
	// Rows actually written, counted by COPY. Includes lines that could not
	// be parsed, since those are kept as rows too -- so it is neither the
	// upload's line count nor its parsed count.
	entries    int64
	durationMS float64
}

// copyBatch bounds how many rows are held before a COPY flush. Large enough
// that COPY is efficient, small enough that memory does not track file size.
const copyBatch = 5000

func (a *API) ingest(r *http.Request, caller *store.User, filename string, part *multipart.Part) (*ingestResult, error) {
	started := time.Now()
	ctx := r.Context()

	uploadID := uuid.New()
	key := blob.Key(caller.OrgID.String(), caller.ID.String(), uploadID.String(), started)

	capped := &capReader{r: part, limit: a.Cfg.MaxUploadBytes}

	// One branch compresses to the bucket, the other parses. A pipe rather
	// than a buffer, so neither side has to hold the file.
	pr, pw := io.Pipe()
	tee := io.TeeReader(capped, pw)

	archiveErr := make(chan error, 1)
	go func() {
		// A panic here would otherwise take down the whole process: this runs
		// on its own goroutine, so net/http's per-request recover never sees
		// it. One bad upload must not be a service outage.
		defer func() {
			if rec := recover(); rec != nil {
				a.Log.Error("panic while archiving upload",
					"event", "upload.archive_panic", "upload_id", uploadID, "panic", rec)
				archiveErr <- fmt.Errorf("archive panic: %v", rec)
			}
		}()
		// Closing the read side unblocks the tee's writer if Put bails early,
		// so a storage failure cannot wedge the request.
		defer func() { _ = pr.Close() }()

		cr, cw := io.Pipe()
		go func() {
			// The encoder writes INTO cw. Constructing it with a nil
			// destination and then calling ReadFrom panics on a zero-capacity
			// buffer -- which is exactly what happened the first time.
			// Bounded explicitly. The defaults size the window and worker
			// pool for maximum throughput, which cost ~550 MB of heap per
			// upload regardless of file size -- measured, not guessed. A
			// 1 MB window and a single worker compress an append-only text
			// log nearly as well for a fraction of that.
			enc, err := zstd.NewWriter(cw,
				zstd.WithEncoderLevel(zstd.SpeedDefault),
				zstd.WithEncoderConcurrency(1),
				zstd.WithWindowSize(1<<20),
			)
			if err != nil {
				_ = cw.CloseWithError(err)
				return
			}
			_, copyErr := io.Copy(enc, pr)
			if closeErr := enc.Close(); copyErr == nil {
				copyErr = closeErr
			}
			_ = cw.CloseWithError(copyErr)
		}()

		archiveErr <- a.Blob.Put(ctx, key, cr)
	}()

	head, full, err := parser.HeadReader(tee, 64*1024)
	if err != nil {
		_ = pw.CloseWithError(err)
		<-archiveErr
		return nil, err
	}
	p := parser.Detect(head)
	if p == nil {
		_, _ = io.Copy(io.Discard, full)
		_ = pw.Close()
		<-archiveErr
		return nil, errUnsupportedFormat
	}

	tx, err := a.Store.Begin(ctx)
	if err != nil {
		_ = pw.CloseWithError(err)
		<-archiveErr
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	batch := store.IngestBatch{UploadID: uploadID, OrgID: caller.OrgID, UserID: caller.ID}

	// Partitions must exist before any row lands, so the span is tracked as
	// entries stream past and partitions are created per flush.
	var pending []parser.Entry
	var minTS, maxTS *time.Time
	var copied int64

	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := a.Store.EnsurePartitions(ctx, tx, minTS, maxTS); err != nil {
			return err
		}
		n, err := a.Store.CopyEntries(ctx, tx, batch, pending)
		if err != nil {
			return err
		}
		copied += n
		pending = pending[:0]
		return nil
	}

	stats, parseErr := p.Parse(full, func(e parser.Entry) error {
		if e.TS != nil {
			if minTS == nil || e.TS.Before(*minTS) {
				t := *e.TS
				minTS = &t
			}
			if maxTS == nil || e.TS.After(*maxTS) {
				t := *e.TS
				maxTS = &t
			}
		}
		pending = append(pending, e)
		if len(pending) >= copyBatch {
			return flush()
		}
		return nil
	})

	// Close the tee's write side so the archive goroutine can finish, whatever
	// happened above.
	_ = pw.CloseWithError(parseErr)
	if parseErr != nil {
		<-archiveErr
		if errors.Is(parseErr, errTooLarge) {
			return nil, errTooLarge
		}
		return nil, parseErr
	}
	if err := flush(); err != nil {
		<-archiveErr
		return nil, err
	}
	if err := <-archiveErr; err != nil {
		return nil, fmt.Errorf("archiving raw upload: %w", err)
	}
	if stats.LineCount == 0 {
		return nil, errEmptyFile
	}

	upload := &store.Upload{
		ID: uploadID, OrgID: caller.OrgID, UserID: caller.ID,
		Filename: filename, ByteSize: capped.read,
		LineCount: stats.LineCount, ParsedCount: stats.ParsedCount,
		Format: p.Key(), ObjectKey: key,
	}
	if err := a.Store.CreateUpload(ctx, tx, upload); err != nil {
		return nil, err
	}
	if err := a.Store.BuildRollups(ctx, tx, batch); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &ingestResult{
		upload:     upload,
		entries:    copied,
		durationMS: float64(time.Since(started).Microseconds()) / 1000.0,
	}, nil
}

var (
	errUnsupportedFormat = errors.New("unrecognised log format")
	errEmptyFile         = errors.New("file is empty")
)

func (a *API) failIngest(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTooLarge):
		httpx.Fail(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("File exceeds the %d MB limit", a.Cfg.MaxUploadBytes/(1024*1024)))
	case errors.Is(err, errEmptyFile):
		httpx.Fail(w, http.StatusBadRequest, "File is empty")
	case errors.Is(err, errUnsupportedFormat):
		httpx.Fail(w, http.StatusBadRequest,
			"Could not recognise this log format. Expected a delimited file with a header row naming its columns (supported: "+
				strings.Join(parser.Keys(), ", ")+").")
	default:
		a.Log.Error("ingest failed", "event", "upload.failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not process the upload")
	}
}

func hasAllowedSuffix(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range allowedSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// readSmallField reads a short form value, bounded so a form field cannot be
// used to allocate without limit.
func readSmallField(part *multipart.Part) string {
	b, _ := io.ReadAll(io.LimitReader(part, 1024))
	return strings.TrimSpace(string(b))
}

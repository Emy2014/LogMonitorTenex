// Package blob archives raw uploads to object storage.
//
// v1 discarded the original bytes after parsing, which meant an improved
// parser could never re-process history. Keeping them compressed costs very
// little and makes re-parsing a background job rather than a lost cause.
//
// Two implementations behind one interface:
//
//	s3   MinIO locally, or any S3-compatible endpoint. Static credentials.
//	gcs  Google Cloud Storage natively, using the runtime service account.
//
// GCS could be reached through its S3 interoperability API, but that needs
// HMAC keys -- long-lived credentials to mint, store and rotate. The native
// client uses Application Default Credentials, so on Cloud Run there is no
// secret to manage at all.
package blob

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Store is the archive. Small on purpose: ingest writes, re-parsing reads,
// startup checks reachability.
type Store interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Ping(ctx context.Context) error
	Describe() string
}

// Config selects and configures an implementation.
type Config struct {
	Bucket string
	// Endpoint set => S3-compatible. Empty => native GCS.
	Endpoint  string
	AccessKey string
	SecretKey string
	PathStyle bool
}

// New returns the implementation the configuration asks for.
func New(ctx context.Context, cfg Config) (Store, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	if cfg.Endpoint == "" {
		return newGCS(ctx, cfg.Bucket)
	}
	return newS3(cfg)
}

// Key is the archive path for an upload: org/user/date/id, so the prefix is
// both a natural browse order and the shard key the workers use.
func Key(orgID, userID, uploadID string, at time.Time) string {
	return fmt.Sprintf("%s/%s/%s/%s.log.zst",
		orgID, userID, at.UTC().Format("2006/01/02"), uploadID)
}

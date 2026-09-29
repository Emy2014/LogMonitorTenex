package blob

import (
	"context"
	"errors"
	"fmt"
	"io"

	gcs "cloud.google.com/go/storage"
)

type gcsStore struct {
	client *gcs.Client
	bucket string
}

// newGCS authenticates with Application Default Credentials, which on Cloud
// Run is the runtime service account -- no key material anywhere.
func newGCS(ctx context.Context, bucket string) (Store, error) {
	client, err := gcs.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs: %w", err)
	}
	return &gcsStore{client: client, bucket: bucket}, nil
}

func (g *gcsStore) Put(ctx context.Context, key string, r io.Reader) error {
	w := g.client.Bucket(g.bucket).Object(key).NewWriter(ctx)
	w.ContentType = "application/zstd"
	if _, err := io.Copy(w, r); err != nil {
		// Close the writer even on failure, or the resumable upload session
		// is left dangling server-side.
		_ = w.Close()
		return err
	}
	return w.Close()
}

func (g *gcsStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return g.client.Bucket(g.bucket).Object(key).NewReader(ctx)
}

// Delete removes the object. Unlike S3, GCS reports a missing object as an
// error, so that one case is folded back into success to keep the interface's
// idempotence promise.
func (g *gcsStore) Delete(ctx context.Context, key string) error {
	err := g.client.Bucket(g.bucket).Object(key).Delete(ctx)
	if errors.Is(err, gcs.ErrObjectNotExist) {
		return nil
	}
	return err
}

func (g *gcsStore) Ping(ctx context.Context) error {
	if _, err := g.client.Bucket(g.bucket).Attrs(ctx); err != nil {
		return fmt.Errorf("bucket %q: %w", g.bucket, err)
	}
	return nil
}

func (g *gcsStore) Describe() string { return fmt.Sprintf("gcs %s", g.bucket) }

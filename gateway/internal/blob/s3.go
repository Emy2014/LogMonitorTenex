package blob

import (
	"context"
	"fmt"
	"io"
	"net/url"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type s3Store struct {
	client *minio.Client
	bucket string
	host   string
}

func newS3(cfg Config) (Store, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("S3_ENDPOINT: %w", err)
	}
	lookup := minio.BucketLookupAuto
	if cfg.PathStyle {
		lookup = minio.BucketLookupPath
	}
	client, err := minio.New(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:       u.Scheme == "https",
		BucketLookup: lookup,
	})
	if err != nil {
		return nil, err
	}
	return &s3Store{client: client, bucket: cfg.Bucket, host: u.Host}, nil
}

// Put streams r to the bucket. Size -1 means unknown, which lets the client
// upload in parts without the caller having to buffer to find a length.
func (s *s3Store) Put(ctx context.Context, key string, r io.Reader) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, r, -1,
		minio.PutObjectOptions{ContentType: "application/zstd"})
	return err
}

func (s *s3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
}

func (s *s3Store) Ping(ctx context.Context) error {
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("bucket %q does not exist", s.bucket)
	}
	return nil
}

func (s *s3Store) Describe() string { return fmt.Sprintf("s3 %s/%s", s.host, s.bucket) }

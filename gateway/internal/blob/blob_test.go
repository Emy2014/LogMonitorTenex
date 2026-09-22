package blob

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestKeyLayout(t *testing.T) {
	at := time.Date(2024, 3, 14, 8, 0, 2, 0, time.UTC)
	got := Key("org-1", "user-2", "upload-3", at)
	want := "org-1/user-2/2024/03/14/upload-3.log.zst"
	if got != want {
		t.Fatalf("Key() = %q, want %q", got, want)
	}
	// The prefix ordering is load-bearing: it is how an org's uploads are
	// browsed, and it is the shard key the workers will use.
	if !strings.HasPrefix(got, "org-1/user-2/") {
		t.Error("org and user must lead the key")
	}
}

func TestKeyUsesUTC(t *testing.T) {
	// 23:30 in UTC+2 is the previous day in UTC. Bucketing on local time
	// would scatter one day's uploads across two prefixes.
	east := time.FixedZone("UTC+2", 2*60*60)
	at := time.Date(2024, 3, 15, 1, 30, 0, 0, east)
	if got := Key("o", "u", "id", at); !strings.Contains(got, "2024/03/14") {
		t.Fatalf("Key() = %q, want the UTC date 2024/03/14", got)
	}
}

func TestSelectsImplementationFromConfig(t *testing.T) {
	ctx := context.Background()

	// An endpoint means S3-compatible; constructing it must not need network.
	s, err := New(ctx, Config{Bucket: "b", Endpoint: "http://localhost:9000",
		AccessKey: "a", SecretKey: "s", PathStyle: true})
	if err != nil {
		t.Fatalf("s3: %v", err)
	}
	if !strings.HasPrefix(s.Describe(), "s3 ") {
		t.Errorf("want the s3 implementation, got %q", s.Describe())
	}

	if _, err := New(ctx, Config{}); err == nil {
		t.Error("a missing bucket must be refused rather than defaulted")
	}
}

func TestBadEndpointIsRejected(t *testing.T) {
	if _, err := New(context.Background(), Config{Bucket: "b", Endpoint: "://nope"}); err == nil {
		t.Fatal("a malformed endpoint should fail at construction, not at first upload")
	}
}

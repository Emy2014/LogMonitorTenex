// Package queue publishes analysis work for the Python workers.
//
// The job shape is a contract with worker/worker/queue.py; the two must agree
// field for field. Keeping the gateway as the only producer means shard
// boundaries are decided in one place.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	queueKey   = "logmonitor:jobs"
	pendingTTL = time.Hour // matches PARTIAL_TTL_SECONDS on the worker
	// Shard size trades scheduling overhead against parallelism. At 25k rows a
	// 1M-line upload becomes 40 shards, which keeps a small worker pool busy
	// without making fan-in bookkeeping the dominant cost.
	DefaultShardSize = 25000
)

type Job struct {
	Kind               string `json:"kind"` // "map" | "reduce"
	AnalysisID         string `json:"analysis_id"`
	UploadID           string `json:"upload_id"`
	OrgID              string `json:"org_id"`
	UserID             string `json:"user_id"`
	Shard              int    `json:"shard"`
	ShardCount         int    `json:"shard_count"`
	Offset             int    `json:"offset"`
	Limit              int    `json:"limit"`
	Scope              string `json:"scope"`
	BaselineWindowDays *int   `json:"baseline_window_days"`
}

type Publisher struct{ rdb *redis.Client }

func New(redisURL string) (*Publisher, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &Publisher{rdb: redis.NewClient(opt)}, nil
}

func (p *Publisher) Close() error { return p.rdb.Close() }

func (p *Publisher) Ping(ctx context.Context) error { return p.rdb.Ping(ctx).Err() }

// Depth is the number of jobs waiting, for the operator metrics panel.
func (p *Publisher) Depth(ctx context.Context) (int64, error) {
	return p.rdb.LLen(ctx, queueKey).Result()
}

// PublishAnalysis fans an upload out into shards.
//
// The pending counter is written in the same transaction as the jobs, and so
// is visible before any worker can consume one. Setting it afterwards would
// let a fast worker finish a shard, find no counter, and never trigger the
// reduce -- an analysis that silently never completes.
func (p *Publisher) PublishAnalysis(ctx context.Context, base Job, entryCount, shardSize int) (int, error) {
	if shardSize <= 0 {
		shardSize = DefaultShardSize
	}
	shards := (entryCount + shardSize - 1) / shardSize
	if shards < 1 {
		// An upload with no rows still needs one job, or the analysis never
		// reaches a terminal state and the UI polls for ever.
		shards = 1
	}

	pipe := p.rdb.TxPipeline()
	pipe.Set(ctx, fmt.Sprintf("logmonitor:pending:%s", base.AnalysisID), shards, pendingTTL)

	for i := 0; i < shards; i++ {
		job := base
		job.Kind = "map"
		job.Shard = i
		job.ShardCount = shards
		job.Offset = i * shardSize
		job.Limit = shardSize

		payload, err := json.Marshal(job)
		if err != nil {
			return 0, err
		}
		pipe.LPush(ctx, queueKey, payload)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return shards, nil
}

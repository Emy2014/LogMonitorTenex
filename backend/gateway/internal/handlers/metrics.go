package handlers

import (
	"runtime"
	"time"
)

var startedAt = time.Now()

// processMetrics reports this instance's own health. Deliberately thin: the
// numbers a user cares about -- traffic, latency percentiles, success rate --
// are computed from their log data by the dashboard endpoints, not from here.
func (a *API) processMetrics() map[string]any {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]any{
		"uptime_seconds": time.Since(startedAt).Seconds(),
		"collected_at":   time.Now().UTC().Format(time.RFC3339),
		"goroutines":     runtime.NumGoroutine(),
		"memory_mb":      float64(m.Sys) / (1024 * 1024),
		"heap_mb":        float64(m.HeapAlloc) / (1024 * 1024),
		"gc_cycles":      m.NumGC,
		"note":           "Per-instance. User-facing metrics come from /api/dashboard/*.",
	}
}

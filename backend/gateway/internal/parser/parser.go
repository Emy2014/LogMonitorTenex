// Package parser turns raw log bytes into canonical entries.
//
// The seam exists so a second format is a slice append rather than a rewrite.
// Only Zscaler NSS ships today; syslog and Apache/Nginx are the obvious next
// two, and neither should require touching this file beyond the registry.
package parser

import (
	"bufio"
	"io"
	"strings"
	"time"
)

// Entry is one log line, canonicalised.
//
// Deliberately a plain struct rather than the database row type, so parsing
// stays independently testable -- the Python original made the same choice for
// the same reason, and its test suite is the spec this one is held to.
type Entry struct {
	LineNo int
	Raw    string

	TS         *time.Time
	ClientIP   string
	Username   string
	Host       string
	URL        string
	Category   string
	Action     string
	ReqBytes   *int64
	RespBytes  *int64
	UserAgent  string
	ThreatName string

	// Fields the v1 parser discarded. These are what make the dashboard's
	// success rate, latency percentiles and cache hit rate genuinely
	// log-derived rather than invented.
	RespCode    *int
	Method      string
	LatencyMS   *int
	CacheStatus string
	Reason      string
}

// Parsed reports whether anything useful was recovered.
//
// The rule inherited from v1: a line that cannot be read still becomes an
// entry with only Raw set. A parser that silently drops what it does not
// understand hides exactly the malformed lines an analyst cares about.
func (e Entry) Parsed() bool { return e.TS != nil || e.ClientIP != "" }

// Parser is one log format.
type Parser interface {
	// Key is persisted on the upload row.
	Key() string
	// Sniff decides from the first few KB whether this parser applies.
	Sniff(head []byte) bool
	// Parse streams entries to emit. It must not buffer the whole input:
	// ingest is expected to hold flat memory regardless of file size.
	Parse(r io.Reader, emit func(Entry) error) (Stats, error)
}

// Stats summarises a parse run.
type Stats struct {
	LineCount   int
	ParsedCount int
}

var registry []Parser

// Register adds a parser. Called from each implementation's init.
func Register(p Parser) { registry = append(registry, p) }

// Detect picks a parser for the given head, or nil.
func Detect(head []byte) Parser {
	for _, p := range registry {
		if p.Sniff(head) {
			return p
		}
	}
	return nil
}

// ByKey returns a registered parser by its key.
func ByKey(key string) Parser {
	for _, p := range registry {
		if p.Key() == key {
			return p
		}
	}
	return nil
}

// Keys lists what is registered, for error messages.
func Keys() []string {
	out := make([]string, 0, len(registry))
	for _, p := range registry {
		out = append(out, p.Key())
	}
	return out
}

// HeadReader peeks the first n bytes without consuming them, so a parser can
// be chosen and then handed the complete stream.
func HeadReader(r io.Reader, n int) ([]byte, io.Reader, error) {
	br := bufio.NewReaderSize(r, n)
	head, err := br.Peek(n)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return nil, nil, err
	}
	return head, br, nil
}

// Normalize reduces a header cell to comparable form: lowercase alphanumerics.
// Matches the Python _normalize exactly, so alias tables port verbatim.
func Normalize(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

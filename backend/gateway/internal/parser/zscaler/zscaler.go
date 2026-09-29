// Package zscaler parses ZScaler NSS Web Proxy logs.
//
// NSS feeds are delimited text with an operator-configured field order, so
// this keys off the header row rather than fixed column positions and maps
// known header names through aliases. Ported from the Python implementation;
// its 12 test cases are carried over as the specification.
package zscaler

import (
	"encoding/csv"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/logmonitor/gateway/internal/parser"
)

func init() { parser.Register(New()) }

// Canonical field -> the header names NSS (and common variants) emit.
// Normalised to lowercase alphanumerics, matching parser.Normalize.
var fieldAliases = map[string][]string{
	"ts":         {"datetime", "eventtime", "time", "timestamp", "date", "logtime"},
	"client_ip":  {"clientip", "clientinternalip", "cip", "clientpublicip", "srcip"},
	"username":   {"login", "user", "username", "userid"},
	"host":       {"host", "hostname", "serverhost"},
	"url":        {"url", "requesturl", "uri"},
	"category":   {"urlcategory", "urlsupercategory", "urlclass", "category"},
	"action":     {"action", "eventaction", "policyaction"},
	"req_bytes":  {"requestsize", "reqsize", "sentbytes", "bytesout"},
	"resp_bytes": {"responsesize", "respsize", "receivedbytes", "bytesin"},
	"user_agent": {"useragent", "useragentheader", "ua"},
	"threat_name": {"threatname", "malwarename", "threat", "virusname"},

	// Added in v2. Without these the dashboard's headline numbers would have
	// to be invented rather than measured.
	"resp_code":    {"respcode", "statuscode", "status", "httpstatus"},
	"latency_ms":   {"totaltime", "requesttime", "responsetime", "duration", "timetaken"},
	"method":       {"requestmethod", "method", "httpmethod"},
	"cache_status": {"cachehit", "tcpstatus", "cachestatus", "cached"},
	// The proxy's own explanation for the action it took. Counting a failure
	// is not the same as knowing why it failed.
	"reason": {"reason", "statusreason", "blockreason", "policyreason"},
}

// Timestamp layouts seen across NSS configurations, most specific first.
var tsLayouts = []string{
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"2006/01/02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"Jan _2 15:04:05",
	time.RFC3339,
}

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Key() string { return "zscaler_nss" }

// Sniff looks for a delimited header row naming at least two fields we know.
//
// Two rather than one: a single match is easy to hit by accident (plenty of
// formats have a "date" column), while two named fields in one delimited
// header is a strong signal.
func (p *Parser) Sniff(head []byte) bool {
	line, _, _ := strings.Cut(string(head), "\n")
	if line == "" {
		return false
	}
	delim := detectDelimiter(line)
	known := 0
	for _, cell := range strings.Split(line, string(delim)) {
		n := parser.Normalize(cell)
		for _, aliases := range fieldAliases {
			for _, a := range aliases {
				if a == n {
					known++
					break
				}
			}
		}
	}
	return known >= 2
}

func detectDelimiter(line string) rune {
	best, bestN := ',', strings.Count(line, ",")
	for _, d := range []struct {
		r rune
		s string
	}{{'\t', "\t"}, {'|', "|"}} {
		if n := strings.Count(line, d.s); n > bestN {
			best, bestN = d.r, n
		}
	}
	return best
}

func (p *Parser) Parse(r io.Reader, emit func(parser.Entry) error) (parser.Stats, error) {
	var stats parser.Stats

	head, full, err := parser.HeadReader(r, 64*1024)
	if err != nil {
		return stats, err
	}
	firstLine, _, _ := strings.Cut(string(head), "\n")

	cr := csv.NewReader(full)
	cr.Comma = detectDelimiter(firstLine)
	// NSS rows vary in width between tenants and even between records; a
	// short row should lose its trailing fields, not abort the whole file.
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.ReuseRecord = true

	header, err := cr.Read()
	if err == io.EOF {
		return stats, nil
	}
	if err != nil {
		return stats, err
	}
	stats.LineCount++
	cols := buildColumnMap(header)

	for lineNo := 2; ; lineNo++ {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A malformed record is still a line that existed. Record it raw
			// rather than discarding it or failing the upload.
			stats.LineCount++
			if emitErr := emit(parser.Entry{LineNo: lineNo, Raw: ""}); emitErr != nil {
				return stats, emitErr
			}
			continue
		}
		stats.LineCount++

		e := buildEntry(lineNo, row, cols, cr.Comma)
		if e.Parsed() {
			stats.ParsedCount++
		}
		if err := emit(e); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func buildColumnMap(header []string) map[string]int {
	normalized := make([]string, len(header))
	for i, h := range header {
		normalized[i] = parser.Normalize(h)
	}
	cols := map[string]int{}
	for canonical, aliases := range fieldAliases {
		for _, alias := range aliases {
			for i, n := range normalized {
				if n == alias {
					if _, taken := cols[canonical]; !taken {
						cols[canonical] = i
					}
					break
				}
			}
			if _, taken := cols[canonical]; taken {
				break
			}
		}
	}
	return cols
}

func buildEntry(lineNo int, row []string, cols map[string]int, delim rune) parser.Entry {
	e := parser.Entry{LineNo: lineNo, Raw: strings.Join(row, string(delim))}

	cell := func(field string) string {
		i, ok := cols[field]
		if !ok || i >= len(row) {
			return ""
		}
		return clean(row[i])
	}

	if v := cell("ts"); v != "" {
		e.TS = parseTS(v)
	}
	if v := cell("client_ip"); v != "" {
		e.ClientIP = parseIP(v)
	}
	e.Username = cell("username")
	e.URL = cell("url")
	e.Host = cell("host")
	if e.Host == "" {
		e.Host = hostFromURL(e.URL)
	}
	e.Category = cell("category")
	e.Action = cell("action")
	e.UserAgent = cell("user_agent")
	e.ThreatName = cell("threat_name")
	e.Method = strings.ToUpper(cell("method"))
	e.CacheStatus = cell("cache_status")
	e.Reason = cell("reason")

	e.ReqBytes = parseInt64(cell("req_bytes"))
	e.RespBytes = parseInt64(cell("resp_bytes"))
	e.RespCode = parseInt(cell("resp_code"))
	e.LatencyMS = parseInt(cell("latency_ms"))
	return e
}

// clean mirrors the Python _clean: NSS writes these for absent values.
func clean(v string) string {
	v = strings.Trim(strings.TrimSpace(v), `"`)
	switch v {
	case "", "-", "None", "NA", "N/A":
		return ""
	}
	return v
}

func parseTS(v string) *time.Time {
	// Epoch seconds or milliseconds.
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n > 1_000_000_000_000 {
			n /= 1000
		}
		t := time.Unix(n, 0).UTC()
		return &t
	}
	for _, layout := range tsLayouts {
		t, err := time.Parse(layout, v)
		if err != nil {
			continue
		}
		if t.Location() == time.UTC && t.Year() == 0 {
			// "Jan _2 15:04:05" carries no year; it would land in year 0 and
			// then in the DEFAULT partition. Assume the current year.
			t = t.AddDate(time.Now().UTC().Year(), 0, 0)
		}
		t = t.UTC()
		return &t
	}
	return nil
}

func parseIP(v string) string {
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return ""
	}
	return addr.String()
}

func parseInt64(v string) *int64 {
	if v == "" {
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		if err != nil {
			return nil
		}
		f = 0
	}
	n := int64(f)
	return &n
}

func parseInt(v string) *int {
	n64 := parseInt64(v)
	if n64 == nil {
		return nil
	}
	n := int(*n64)
	return &n
}

func hostFromURL(u string) string {
	if u == "" {
		return ""
	}
	s := u
	if _, after, found := strings.Cut(s, "://"); found {
		s = after
	}
	s, _, _ = strings.Cut(s, "/")
	s, _, _ = strings.Cut(s, ":")
	return s
}

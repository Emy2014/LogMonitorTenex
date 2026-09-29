package zscaler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/logmonitor/gateway/internal/parser"
)

func parseAll(t *testing.T, text string) ([]parser.Entry, parser.Stats) {
	t.Helper()
	var out []parser.Entry
	stats, err := New().Parse(strings.NewReader(text), func(e parser.Entry) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return out, stats
}

// The real NSS header, as it appears in samples/. Field order is
// tenant-configured, which is why the parser keys off names not positions.
const nssHeader = "datetime,recordid,login,department,location,ClientIP,clientpublicIP," +
	"serverip,requestmethod,requestsize,responsesize,transactionsize,url,refererURL,host," +
	"urlcategory,urlsupercategory,urlclass,action,reason,respcode,useragent,threatname," +
	"threatcategory,threatclass,appname,appclass,pagerisk,filetype,dlpengine,dlpdictionaries," +
	"contenttype,proto,devicehostname,deviceowner"

func TestParsesRealNSSHeader(t *testing.T) {
	row := "2024-03-14 08:00:02,1111,m.chen,Finance,HQ,10.12.7.88,198.51.100.112,93.184.170.182," +
		"GET,881,15705,16586,https://stackoverflow.com/api/v2/items,,stackoverflow.com," +
		"Professional Services,Information Technology,Business Use,Allowed,Allowed,200," +
		`"Mozilla/5.0 (Windows NT 10.0) Chrome/131.0.0.0",,None,None,General Browsing,` +
		"General Browsing,0,None,None,None,text/html,HTTPS,CHEN-LT-32,m.chen"

	entries, stats := parseAll(t, nssHeader+"\n"+row+"\n")
	if len(entries) != 1 || stats.ParsedCount != 1 {
		t.Fatalf("want 1 parsed entry, got %d entries / %d parsed", len(entries), stats.ParsedCount)
	}

	e := entries[0]
	if e.TS == nil || e.TS.Format("2006-01-02 15:04:05") != "2024-03-14 08:00:02" {
		t.Errorf("ts = %v", e.TS)
	}
	for _, c := range []struct{ got, want, name string }{
		{e.ClientIP, "10.12.7.88", "client_ip"},
		{e.Username, "m.chen", "username"},
		{e.Host, "stackoverflow.com", "host"},
		{e.Category, "Professional Services", "category"},
		{e.Action, "Allowed", "action"},
		{e.Method, "GET", "method"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	// The four fields v1 discarded.
	if e.RespCode == nil || *e.RespCode != 200 {
		t.Errorf("resp_code = %v, want 200", e.RespCode)
	}
	if e.ReqBytes == nil || *e.ReqBytes != 881 {
		t.Errorf("req_bytes = %v, want 881", e.ReqBytes)
	}
	if e.RespBytes == nil || *e.RespBytes != 15705 {
		t.Errorf("resp_bytes = %v, want 15705", e.RespBytes)
	}
	if !strings.Contains(e.UserAgent, "Chrome") {
		t.Errorf("user_agent = %q", e.UserAgent)
	}
}

// The rule the whole design hangs on: an unreadable line still becomes a row.
func TestUnparseableLineStillBecomesAnEntry(t *testing.T) {
	entries, stats := parseAll(t, "datetime,ClientIP,url\nnot-a-date,not-an-ip,\n")
	if len(entries) != 1 {
		t.Fatalf("want the bad line kept, got %d entries", len(entries))
	}
	if entries[0].Parsed() {
		t.Error("an entry with neither timestamp nor IP must not count as parsed")
	}
	if entries[0].Raw == "" {
		t.Error("raw must be preserved so the line is not lost")
	}
	if stats.ParsedCount != 0 || stats.LineCount != 2 {
		t.Errorf("stats = %+v, want 2 lines / 0 parsed", stats)
	}
}

func TestColumnOrderIsIrrelevant(t *testing.T) {
	a, _ := parseAll(t, "datetime,ClientIP,url\n2024-03-14 08:00:02,10.0.0.1,http://x.io/a\n")
	b, _ := parseAll(t, "url,ClientIP,datetime\nhttp://x.io/a,10.0.0.1,2024-03-14 08:00:02\n")

	if a[0].ClientIP != b[0].ClientIP || a[0].URL != b[0].URL ||
		a[0].TS.Equal(*b[0].TS) == false {
		t.Fatalf("reordering the header changed the result:\n %+v\n %+v", a[0], b[0])
	}
}

func TestTabAndPipeDelimited(t *testing.T) {
	for name, text := range map[string]string{
		"tab":  "datetime\tClientIP\turl\n2024-03-14 08:00:02\t10.0.0.1\thttp://x.io/a\n",
		"pipe": "datetime|ClientIP|url\n2024-03-14 08:00:02|10.0.0.1|http://x.io/a\n",
	} {
		t.Run(name, func(t *testing.T) {
			entries, _ := parseAll(t, text)
			if len(entries) != 1 || entries[0].ClientIP != "10.0.0.1" {
				t.Fatalf("got %+v", entries)
			}
		})
	}
}

func TestTimestampFormats(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2024-03-14 08:00:02", "2024-03-14 08:00:02"},
		{"2024-03-14T08:00:02", "2024-03-14 08:00:02"},
		{"2024-03-14T08:00:02Z", "2024-03-14 08:00:02"},
		{"2024/03/14 08:00:02", "2024-03-14 08:00:02"},
		{"14/Mar/2024:08:00:02 +0000", "2024-03-14 08:00:02"},
		{"1710403202", "2024-03-14 08:00:02"},      // epoch seconds
		{"1710403202000", "2024-03-14 08:00:02"},   // epoch milliseconds
	} {
		t.Run(tc.in, func(t *testing.T) {
			entries, _ := parseAll(t, "datetime,ClientIP\n"+tc.in+",10.0.0.1\n")
			if entries[0].TS == nil {
				t.Fatalf("%q did not parse", tc.in)
			}
			if got := entries[0].TS.UTC().Format("2006-01-02 15:04:05"); got != tc.want {
				t.Fatalf("%q -> %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAbsentValueMarkers(t *testing.T) {
	entries, _ := parseAll(t,
		"datetime,ClientIP,login,threatname,respcode\n2024-03-14 08:00:02,10.0.0.1,-,None,N/A\n")
	e := entries[0]
	if e.Username != "" || e.ThreatName != "" {
		t.Errorf(`"-" and "None" should read as absent, got %q / %q`, e.Username, e.ThreatName)
	}
	if e.RespCode != nil {
		t.Errorf("N/A should read as absent, got %v", e.RespCode)
	}
}

func TestHostFallsBackToURL(t *testing.T) {
	entries, _ := parseAll(t,
		"datetime,ClientIP,url\n2024-03-14 08:00:02,10.0.0.1,https://files.example.com:8443/a/b\n")
	if entries[0].Host != "files.example.com" {
		t.Fatalf("host = %q, want files.example.com", entries[0].Host)
	}
}

func TestInvalidIPIsDropped(t *testing.T) {
	entries, _ := parseAll(t, "datetime,ClientIP\n2024-03-14 08:00:02,not-an-ip\n")
	if entries[0].ClientIP != "" {
		t.Fatalf("client_ip = %q, want empty", entries[0].ClientIP)
	}
	// The timestamp still parsed, so the entry counts as parsed.
	if !entries[0].Parsed() {
		t.Error("a recoverable timestamp should still mark the entry parsed")
	}
}

func TestShortRowDoesNotAbortTheFile(t *testing.T) {
	// A truncated row should lose its trailing fields, not the whole upload.
	entries, stats := parseAll(t,
		"datetime,ClientIP,url,respcode\n2024-03-14 08:00:02,10.0.0.1\n2024-03-14 08:00:03,10.0.0.2,http://x.io,200\n")
	if len(entries) != 2 {
		t.Fatalf("want both rows, got %d", len(entries))
	}
	if stats.ParsedCount != 2 {
		t.Errorf("both rows recovered a timestamp; parsed = %d", stats.ParsedCount)
	}
	if entries[0].RespCode != nil {
		t.Error("a missing trailing field should be absent, not garbage")
	}
}

func TestEmptyInput(t *testing.T) {
	entries, stats := parseAll(t, "")
	if len(entries) != 0 || stats.LineCount != 0 {
		t.Fatalf("empty input should yield nothing, got %d entries %+v", len(entries), stats)
	}
}

func TestHeaderOnly(t *testing.T) {
	entries, stats := parseAll(t, nssHeader+"\n")
	if len(entries) != 0 {
		t.Fatalf("a header with no rows should yield no entries, got %d", len(entries))
	}
	if stats.LineCount != 1 {
		t.Errorf("line count = %d, want 1", stats.LineCount)
	}
}

func TestSniff(t *testing.T) {
	p := New()
	if !p.Sniff([]byte(nssHeader + "\n2024-03-14 08:00:02,...")) {
		t.Error("the real NSS header should sniff true")
	}
	if !p.Sniff([]byte("datetime,ClientIP,url\n")) {
		t.Error("a minimal known header should sniff true")
	}
	// Two unrelated columns must not be claimed.
	if p.Sniff([]byte("alpha,beta,gamma\n1,2,3\n")) {
		t.Error("an unrelated CSV should sniff false")
	}
	if p.Sniff([]byte("Mar 14 08:00:02 host sshd[1]: accepted\n")) {
		t.Error("syslog should sniff false")
	}
}

// Parity against the real fixtures: the numbers here are what the Python
// implementation produces, so a regression in the port shows up as a diff.
func TestAgainstRealSamples(t *testing.T) {
	for name, wantLines := range map[string]int{
		"zscaler_benign.log":     1201,
		"zscaler_suspicious.log": 2965,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "..", "samples", name)
			f, err := os.Open(path)
			if err != nil {
				t.Skipf("sample not available: %v", err)
			}
			defer f.Close()

			var parsed, withCode, withMethod int
			stats, err := New().Parse(f, func(e parser.Entry) error {
				if e.Parsed() {
					parsed++
				}
				if e.RespCode != nil {
					withCode++
				}
				if e.Method != "" {
					withMethod++
				}
				return nil
			})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if stats.LineCount != wantLines {
				t.Errorf("line count = %d, want %d", stats.LineCount, wantLines)
			}
			// Every data row in the fixtures is well formed.
			if parsed != wantLines-1 {
				t.Errorf("parsed = %d, want %d", parsed, wantLines-1)
			}
			// The v2 fields must actually be populated, or the dashboard has
			// nothing to chart.
			if withCode != wantLines-1 {
				t.Errorf("resp_code populated on %d of %d rows", withCode, wantLines-1)
			}
			if withMethod != wantLines-1 {
				t.Errorf("method populated on %d of %d rows", withMethod, wantLines-1)
			}
		})
	}
}

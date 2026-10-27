package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/duketopceo/OmaSeal/engine/ui"
)

// Every successful secret read is counted: `get`, `reveal`, and `resolve`
// are logged by their CLI handlers, while MCP/IPC read paths emit an
// explicit `access` line so agent traffic is tallied too.
var accessLogRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?:get|reveal|resolve|access)\s+(.+?)(?:\s+chain=[0-9a-f]{64})?\s*$`)

// opTelemetryRe matches the structured failure lines emitted by logOpResult.
// Only failures are logged — successes already have stats lines — so every
// match is an error or timeout worth counting.
var opTelemetryRe = regexp.MustCompile(`^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+op=(\S+)\s+target="([^"]*)"\s+dur=(\d+)ms\s+result=(\w+)\s+code=(\S+?)(?:\s+chain=[0-9a-f]{64})?\s*$`)

// OpTelemetry aggregates the failure telemetry lines — the layer that makes
// wedged-daemon hangs, manifest denials, and error bursts visible.
type OpTelemetry struct {
	Failures  int            `json:"failures"`
	Timeouts  int            `json:"timeouts"`
	SlowestMs int64          `json:"slowest_ms"`
	ByCode    map[string]int `json:"by_code,omitempty"`
}

// AccessStat records the usage frequency and recency for a given secret.
type AccessStat struct {
	Service      string    `json:"service"`
	Account      string    `json:"account"`
	Count        int       `json:"access_count"`
	LastAccessed time.Time `json:"last_accessed"`
}

// AnalyticsReport is the top-level summary of keyring usage.
type AnalyticsReport struct {
	TotalAccesses int          `json:"total_accesses"`
	UniqueSecrets int          `json:"unique_secrets"`
	Stats         []AccessStat `json:"stats"`
	Telemetry     *OpTelemetry `json:"telemetry,omitempty"`
}

// statKey is the canonical map key for a credential: the exact
// "service/account" payload as logged. It is deliberately case-sensitive
// (Secret Service attribute matching is case-sensitive) and unsplit — items
// whose service or account contains "/" still match their own log lines.
func statKey(service, account string) string {
	return service + "/" + account
}

// logHistory returns the live log path preceded by its rotated siblings
// (omaseal.log.N), oldest first — so stats and telemetry survive rotation
// and the logMaxBytes truncation.
func logHistory(path string) []string {
	var out []string
	if matches, _ := filepath.Glob(path + ".*"); true {
		var rotated []string
		for _, m := range matches {
			suffix := m[len(path):]
			if n, err := strconv.Atoi(suffix[1:]); err == nil && n > 0 {
				rotated = append(rotated, m)
			}
		}
		sort.Strings(rotated)
		out = append(out, rotated...)
	}
	return append(out, path)
}

// ParseAccessLogs reads the OmaSeal log file (plus any rotated siblings)
// and aggregates access statistics.
func ParseAccessLogs() (map[string]AccessStat, error) {
	path := LogPath()
	if path == "" {
		return nil, fmt.Errorf("cannot determine log path: %v", logInitErr)
	}
	merged := make(map[string]AccessStat)
	for _, p := range logHistory(path) {
		part, err := ParseAccessLogsFromFile(p)
		if err != nil {
			return nil, err
		}
		for k, s := range part {
			if cur, ok := merged[k]; ok {
				cur.Count += s.Count
				if s.LastAccessed.After(cur.LastAccessed) {
					cur.LastAccessed = s.LastAccessed
				}
				merged[k] = cur
			} else {
				merged[k] = s
			}
		}
	}
	return merged, nil
}

// ParseAccessLogsFromFile parses access statistics from a given log file.
func ParseAccessLogsFromFile(path string) (map[string]AccessStat, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]AccessStat), nil
		}
		return nil, err
	}
	defer f.Close()

	stats := make(map[string]AccessStat)
	scanner := bufio.NewScanner(f)
	// WriteLog bounds field lengths, but a pre-existing or hand-edited log
	// could hold longer lines; 1 MiB headroom keeps one giant line from
	// erroring every stats call.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	layout := "2006/01/02 15:04:05"

	for scanner.Scan() {
		line := scanner.Text()
		m := accessLogRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		// WriteLog stamps local time; parse in the local zone so
		// last_accessed is not shifted by the host's UTC offset.
		ts, err := time.ParseInLocation(layout, m[1], time.Local)
		if err != nil {
			continue
		}

		// Key by the exact logged payload so services containing "/" match
		// their items. The stored Service/Account split is display-only —
		// first-"/" is always correct for OmaSeal-written items.
		service, account, ok := strings.Cut(m[2], "/")
		if !ok {
			continue
		}
		k := m[2]

		cur, ok := stats[k]
		if !ok {
			stats[k] = AccessStat{
				Service:      service,
				Account:      account,
				Count:        1,
				LastAccessed: ts,
			}
		} else {
			cur.Count++
			if ts.After(cur.LastAccessed) {
				cur.LastAccessed = ts
			}
			stats[k] = cur
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}

// ParseOpTelemetry aggregates the op= telemetry lines from the log file.
// A missing log is not an error — it just means no operations ran yet.
func ParseOpTelemetry(path string) (*OpTelemetry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &OpTelemetry{}, nil
		}
		return nil, err
	}
	defer f.Close()

	t := &OpTelemetry{ByCode: map[string]int{}}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		m := opTelemetryRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		dur, err := strconv.ParseInt(m[3], 10, 64)
		if err != nil {
			continue
		}
		t.Failures++
		if m[4] == "timeout" {
			t.Timeouts++
		}
		t.ByCode[m[5]]++
		if dur > t.SlowestMs {
			t.SlowestMs = dur
		}
	}
	return t, scanner.Err()
}

// GetAnalyticsReport builds a summarized usage report from the access logs.
func GetAnalyticsReport() (*AnalyticsReport, error) {
	statsMap, err := ParseAccessLogs()
	if err != nil {
		return nil, err
	}
	report := BuildAnalyticsReport(statsMap)
	merged := &OpTelemetry{ByCode: map[string]int{}}
	for _, p := range logHistory(LogPath()) {
		telem, terr := ParseOpTelemetry(p)
		if terr != nil {
			continue
		}
		merged.Failures += telem.Failures
		merged.Timeouts += telem.Timeouts
		if telem.SlowestMs > merged.SlowestMs {
			merged.SlowestMs = telem.SlowestMs
		}
		for code, n := range telem.ByCode {
			merged.ByCode[code] += n
		}
	}
	if merged.Failures > 0 {
		report.Telemetry = merged
	}
	return report, nil
}

// BuildAnalyticsReport constructs an AnalyticsReport from an existing stats
// map, sorted most-used first. Consumers slice the prefix they want.
func BuildAnalyticsReport(statsMap map[string]AccessStat) *AnalyticsReport {
	var statsList []AccessStat
	total := 0
	for _, s := range statsMap {
		statsList = append(statsList, s)
		total += s.Count
	}

	sort.Slice(statsList, func(i, j int) bool {
		if statsList[i].Count != statsList[j].Count {
			return statsList[i].Count > statsList[j].Count
		}
		return statsList[i].LastAccessed.After(statsList[j].LastAccessed)
	})

	return &AnalyticsReport{
		TotalAccesses: total,
		UniqueSecrets: len(statsList),
		Stats:         statsList,
	}
}

// EnrichItemsWithStats decorates Item structs with access count and last accessed time.
func EnrichItemsWithStats(items []Item, stats map[string]AccessStat) []Item {
	for i := range items {
		k := statKey(items[i].Service, items[i].Account)
		if stat, ok := stats[k]; ok {
			items[i].AccessCount = stat.Count
			t := stat.LastAccessed
			items[i].LastAccessed = &t
		}
	}
	return items
}

// EnrichItemsWithFlags decorates Item structs with rotation-flag state so
// every list surface (CLI, IPC, MCP) carries the alert without each caller
// re-implementing the lookup. An unreadable flags file degrades to no
// markers — a flag-store hiccup must not break listing.
func EnrichItemsWithFlags(items []Item) []Item {
	flags, err := loadFlags()
	if err != nil {
		WriteLog("list: flags load failed, rotation markers empty: %v", err)
		return items
	}
	for i := range items {
		if f, ok := flags[statKey(items[i].Service, items[i].Account)]; ok {
			items[i].RotationFlagged = true
			items[i].RotationReason = f.Reason
		}
	}
	return items
}

// SortItemsByUsage sorts secret items descending by their access count.
// The QML panel mirrors this comparator for its "used" sort mode — keep
// the two orderings in sync.
func SortItemsByUsage(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].AccessCount != items[j].AccessCount {
			return items[i].AccessCount > items[j].AccessCount
		}
		if items[i].LastAccessed != nil && items[j].LastAccessed != nil {
			return items[i].LastAccessed.After(*items[j].LastAccessed)
		}
		if items[i].LastAccessed != nil {
			return true
		}
		if items[j].LastAccessed != nil {
			return false
		}
		return statKey(items[i].Service, items[i].Account) < statKey(items[j].Service, items[j].Account)
	})
}

// SortItemsByRecency sorts secret items by last access, most recent first;
// items never accessed fall to the bottom sorted by name.
func SortItemsByRecency(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastAccessed != nil && items[j].LastAccessed != nil {
			return items[i].LastAccessed.After(*items[j].LastAccessed)
		}
		if items[i].LastAccessed != nil {
			return true
		}
		if items[j].LastAccessed != nil {
			return false
		}
		return statKey(items[i].Service, items[i].Account) < statKey(items[j].Service, items[j].Account)
	})
}

// listWithUsage is the shared list+enrich+sort pipeline used by the CLI,
// IPC, and MCP list surfaces so all three return identical ordering.
// sortMode is "used", "recent", "name", or "" (name order, the default).
func listWithUsage(service, sortMode string) ([]Item, error) {
	items, _, err := listWithUsageStatus(service, sortMode)
	return items, err
}

// listWithUsageStatus is listWithUsage plus a usageAvailable flag: false means
// the access log failed to parse and every usage field is a zero value —
// callers that lint on usage must not report staleness they can't see.
func listWithUsageStatus(service, sortMode string) ([]Item, bool, error) {
	items, err := List(service)
	if err != nil {
		return nil, false, err
	}
	usageAvailable := true
	stats, serr := ParseAccessLogs()
	if serr != nil {
		WriteLog("list: access-log parse failed, usage columns empty: %v", serr)
		usageAvailable = false
	} else if stats != nil {
		items = EnrichItemsWithStats(items, stats)
	}
	items = EnrichItemsWithFlags(items)
	switch sortMode {
	case "used", "hits":
		SortItemsByUsage(items)
	case "recent":
		SortItemsByRecency(items)
	case "", "name":
		// List already returns name order.
	default:
		return nil, usageAvailable, newError("invalid_sort", "omaseal list --sort=used|recent|name",
			fmt.Errorf("unknown sort %q", sortMode))
	}
	return items, usageAvailable, nil
}

// handleStats renders the usage analytics report.
func handleStats() {
	jsonOut := hasFlag(os.Args, "--json")
	report, err := GetAnalyticsReport()
	if err != nil {
		printError("generating analytics: ", err)
		os.Exit(1)
	}

	if jsonOut {
		b, _ := json.Marshal(report)
		fmt.Println(string(b))
		return
	}

	fmt.Printf("OmaSeal Keyring Usage Analytics\n")
	fmt.Printf("Total Secret Accesses: %d\n", report.TotalAccesses)
	fmt.Printf("Unique Secrets Accessed: %d\n", report.UniqueSecrets)
	if report.Telemetry != nil {
		t := report.Telemetry
		fmt.Printf("Failed operations: %d (timeouts: %d, slowest: %dms)\n", t.Failures, t.Timeouts, t.SlowestMs)
		if len(t.ByCode) > 0 {
			codes := make([]string, 0, len(t.ByCode))
			for c := range t.ByCode {
				codes = append(codes, c)
			}
			sort.Strings(codes)
			parts := make([]string, 0, len(codes))
			for _, c := range codes {
				parts = append(parts, fmt.Sprintf("%s×%d", c, t.ByCode[c]))
			}
			fmt.Printf("Failure codes: %s\n", strings.Join(parts, ", "))
		}
	}
	fmt.Println()

	if len(report.Stats) == 0 {
		fmt.Println("No secret access activity recorded yet.")
		return
	}

	const topN = 20
	top := report.Stats
	if len(top) > topN {
		top = top[:topN]
	}
	rows := make([][]string, 0, len(top))
	for i, stat := range top {
		last := stat.LastAccessed.Format("2006-01-02 15:04:05")
		rows = append(rows, []string{fmt.Sprintf("#%d", i+1), strconv.Itoa(stat.Count), sanitizeField(stat.Service), sanitizeField(stat.Account), last})
	}
	ui.Table(os.Stdout, 3, []string{"RANK", "HITS", "SERVICE", "ACCOUNT", "LAST ACCESSED"}, rows)
	if len(report.Stats) > topN {
		fmt.Printf("\n… and %d more (use --json for the full list)\n", len(report.Stats)-topN)
	}
}

// maxSanitizeRunes caps a sanitized metadata field — a hostile item name
// must not flood a log line or terminal scrollback with megabytes of text.
const maxSanitizeRunes = 200

// sanitizeField strips control characters from keyring metadata before it
// reaches a terminal, log line, or generated file — C0, DEL, and C1
// (U+0080–U+009F, where single-byte CSI/SGR-equivalent controls live).
// Foreign items can carry arbitrary attribute strings; OmaSeal-written
// names are already charset-constrained by validComponent. Output is
// capped at maxSanitizeRunes with a visible truncation marker.
func sanitizeField(s string) string {
	n := 0
	truncated := false
	out := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		if n >= maxSanitizeRunes {
			truncated = true
			return -1
		}
		n++
		return r
	}, s)
	if truncated {
		out += "…"
	}
	return out
}

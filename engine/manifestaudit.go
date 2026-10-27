package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/duketopceo/OmaSeal/engine/ui"
)

// staleThresholdDays bounds the "stale" lint: items whose last recorded read is
// older than this (or which have never been read at all) are flagged. Usage
// stats come from the access log, so this measures agent/CLI reads — a stale
// flag means "nobody has asked for this in a while", not "the secret is bad".
const staleThresholdDays = 90

// AuditFinding is one linter observation about the manifest vs. the live
// keyring inventory. Kinds: dead_rule, uncovered, stale, advisory.
type AuditFinding struct {
	Kind   string `json:"kind"`
	Target string `json:"target"` // rule pattern or service/account
	Detail string `json:"detail"`
}

// ProposalChange is one suggested manifest edit. expands_access is a display
// hint written by generators; apply recomputes expansion from the parsed change
// and never trusts this field.
type ProposalChange struct {
	Action        string  `json:"action"` // add | remove | set
	Policy        string  `json:"policy"` // ALLOW | ASK | DENY (add/set)
	Pattern       string  `json:"pattern"`
	Description   string  `json:"description"`
	Rationale     string  `json:"rationale,omitempty"`
	Confidence    float64 `json:"confidence,omitempty"`
	ExpandsAccess bool    `json:"expands_access"`
	ReducesAccess bool    `json:"reduces_access,omitempty"`
}

// Proposal is the file passed between `manifest audit --proposal` (or the Jev
// companion) and `manifest apply`. manifest_sha256 binds the proposal to the
// exact manifest bytes it was generated against.
type Proposal struct {
	Version        int              `json:"version"`
	GeneratedAt    time.Time        `json:"generated_at"`
	Generator      string           `json:"generator"` // "omaseal audit" | "jev"
	ManifestSHA256 string           `json:"manifest_sha256"`
	Findings       []AuditFinding   `json:"findings,omitempty"`
	Changes        []ProposalChange `json:"changes"`
}

// patternMatches mirrors Manifest.CheckPolicy's match order: exact
// service/account, then service wildcard, then catch-all. Shared semantics keep
// the linter's coverage view identical to enforcement.
func patternMatches(pattern, service, account string) bool {
	target := strings.ToLower(service) + "/" + strings.ToLower(account)
	if strings.EqualFold(pattern, target) {
		return true
	}
	if strings.EqualFold(pattern, strings.ToLower(service)+"/*") {
		return true
	}
	return pattern == "*" || pattern == "*/*"
}

func isCatchAll(pattern string) bool {
	return pattern == "*" || pattern == "*/*"
}

// auditManifest lints rules against the live inventory. The item list must be
// the unfiltered keyring inventory — filtering DENY'd items here would let a
// wrong rule hide its own evidence. usageAvailable false means the access log
// could not be parsed: stale findings are suppressed rather than reported
// against zero-value usage fields.
func auditManifest(m *Manifest, items []Item, now time.Time, usageAvailable bool) []AuditFinding {
	var findings []AuditFinding

	// Dead rules: a non-catch-all pattern that matches nothing.
	for _, r := range m.Rules {
		if isCatchAll(r.Pattern) {
			continue
		}
		matched := false
		for _, it := range items {
			if patternMatches(r.Pattern, it.Service, it.Account) {
				matched = true
				break
			}
		}
		if !matched {
			findings = append(findings, AuditFinding{
				Kind:   "dead_rule",
				Target: r.Pattern,
				Detail: fmt.Sprintf("%s rule matches no keyring item", r.Policy),
			})
		}
	}

	// Raw-file checks the parsed rules can't express: lines that look like
	// rules but carry an unrecognized policy token (typos, Unicode
	// lookalikes) are silently dropped, and duplicate patterns shadow by
	// first-match.
	if data, err := os.ReadFile(m.Path); err == nil {
		seenPattern := map[string]int{}
		for i, ln := range strings.Split(string(data), "\n") {
			word, valid := lineRuleToken(ln)
			if word == "" {
				continue
			}
			if !valid {
				findings = append(findings, AuditFinding{
					Kind:   "advisory",
					Target: fmt.Sprintf("line %d", i+1),
					Detail: fmt.Sprintf("%q does not start a valid ALLOW/ASK/DENY rule — line ignored", word),
				})
				continue
			}
			_, pattern, _, _ := parseRuleLine(ln)
			key := strings.ToLower(pattern)
			if first, dup := seenPattern[key]; dup {
				findings = append(findings, AuditFinding{
					Kind:   "advisory",
					Target: pattern,
					Detail: fmt.Sprintf("line %d duplicates line %d — the earlier rule wins at equal specificity", i+1, first),
				})
			} else {
				seenPattern[key] = i + 1
			}
		}
	}

	// Duplicate targets: the same service/account listed more than once — a
	// leftover from imports or retries that confuses resolve/list surfaces.
	dupCount := map[string]int{}
	for _, it := range items {
		dupCount[it.Service+"/"+it.Account]++
	}
	reportedDup := map[string]bool{}

	for _, it := range items {
		target := it.Service + "/" + it.Account

		if dupCount[target] > 1 && !reportedDup[target] {
			reportedDup[target] = true
			findings = append(findings, AuditFinding{
				Kind:   "advisory",
				Target: target,
				Detail: fmt.Sprintf("listed %d times — duplicate entries", dupCount[target]),
			})
		}

		hasWhitespace := strings.ContainsAny(it.Service+it.Account, " \t")

		// Uncovered: governed only by the catch-all fallback — no explicit
		// rule. Whitespace names are addressable via quoted patterns, so
		// they're judged like any other item.
		covered := false
		for _, r := range m.Rules {
			if !isCatchAll(r.Pattern) && patternMatches(r.Pattern, it.Service, it.Account) {
				covered = true
				break
			}
		}
		if !covered {
			findings = append(findings, AuditFinding{
				Kind:   "uncovered",
				Target: target,
				Detail: "no explicit rule; fallback policy governs",
			})
		}

		// Stale: never read, or last read older than the threshold. Suppressed
		// when usage telemetry failed to load — a zero-value field is not
		// evidence of staleness.
		if usageAvailable {
			switch {
			case it.AccessCount == 0 && it.LastAccessed == nil:
				findings = append(findings, AuditFinding{
					Kind:   "stale",
					Target: target,
					Detail: "never accessed",
				})
			case it.LastAccessed != nil && now.Sub(*it.LastAccessed) > staleThresholdDays*24*time.Hour:
				findings = append(findings, AuditFinding{
					Kind:   "stale",
					Target: target,
					Detail: fmt.Sprintf("last accessed %d days ago", int(now.Sub(*it.LastAccessed).Hours()/24)),
				})
			}
		}

		// Advisories: names that need quoting, and test-shaped leftovers.
		if hasWhitespace {
			findings = append(findings, AuditFinding{
				Kind:   "advisory",
				Target: target,
				Detail: "name contains whitespace — rules must quote the pattern (DENY \"svc/acct name\")",
			})
		}
		if strings.Contains(it.Service, "/") {
			findings = append(findings, AuditFinding{
				Kind:   "advisory",
				Target: target,
				Detail: "service name contains '/' — wildcards are service-exact (foo/* does NOT match service foo/bar); write " + it.Service + "/* or an exact rule",
			})
		}
		if ls := strings.ToLower(it.Service); ls == "test" || strings.HasPrefix(ls, "test-") || strings.HasPrefix(ls, "test_") {
			findings = append(findings, AuditFinding{
				Kind:   "advisory",
				Target: target,
				Detail: "test-shaped service name — possible leftover from development",
			})
		}
	}

	if !usageAvailable {
		findings = append(findings, AuditFinding{
			Kind:   "advisory",
			Target: "access-log",
			Detail: "usage telemetry unavailable — stale analysis suppressed (cannot distinguish unused from unmeasured)",
		})
	}

	return findings
}

// manifestFileSHA256 hashes the manifest's on-disk bytes. A missing manifest
// hashes as empty so proposals can still bind against "no manifest".
func manifestFileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			data = nil
		} else {
			return "", err
		}
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// writeProposal serializes a proposal atomically at 0600.
func writeProposal(path string, p *Proposal) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileMode(path, data, 0600)
}

// suggestChanges derives the conservative change set the local linter can make
// on its own: dead rules are safe to remove (they match nothing). Everything
// else stays a finding — policy choices belong to the human (or Jev).
func suggestChanges(findings []AuditFinding) []ProposalChange {
	var changes []ProposalChange
	for _, f := range findings {
		if f.Kind == "dead_rule" {
			changes = append(changes, ProposalChange{
				Action:    "remove",
				Pattern:   f.Target,
				Rationale: "rule matches no keyring item",
			})
		}
	}
	return changes
}

// handleManifestAudit implements `omaseal manifest audit [--json] [--proposal <path>]`.
func handleManifestAudit(args []string, jsonOut bool) {
	proposalPath := flagValue(args, "--proposal")

	m, err := LoadManifest()
	if err != nil {
		printError("loading manifest: ", err)
		os.Exit(1)
	}
	items, usageAvailable, err := listWithUsageStatus("", "")
	if err != nil {
		printError("listing secrets for audit: ", err)
		os.Exit(1)
	}

	findings := auditManifest(m, items, time.Now(), usageAvailable)

	if proposalPath != "" {
		sum, err := manifestFileSHA256(m.Path)
		if err != nil {
			printError("hashing manifest: ", err)
			os.Exit(1)
		}
		p := &Proposal{
			Version:        1,
			GeneratedAt:    time.Now().UTC(),
			Generator:      "omaseal audit",
			ManifestSHA256: sum,
			Findings:       findings,
			Changes:        suggestChanges(findings),
		}
		if err := writeProposal(proposalPath, p); err != nil {
			printError("writing proposal: ", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote proposal to %s — review it, then `omaseal manifest apply %s`\n", proposalPath, proposalPath)
	}

	if jsonOut {
		b, _ := json.Marshal(map[string]any{
			"manifest": m.Path,
			"rules":    len(m.Rules),
			"items":    len(items),
			"findings": findings,
		})
		fmt.Println(string(b))
		return
	}

	if len(findings) == 0 {
		fmt.Printf("manifest audit: %d rules over %d items — no findings\n", len(m.Rules), len(items))
		return
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Kind]++
	}
	fmt.Printf("manifest audit: %d rules over %d items — %d dead_rule / %d uncovered / %d stale / %d advisory\n\n",
		len(m.Rules), len(items), counts["dead_rule"], counts["uncovered"], counts["stale"], counts["advisory"])

	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, []string{f.Kind, sanitizeField(f.Target), sanitizeField(f.Detail)})
	}
	ui.Table(os.Stdout, 2, []string{"KIND", "TARGET", "DETAIL"}, rows)
}

// flagValue returns the value after "--flag <value>" or "--flag=value".
func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"=")
		}
	}
	return ""
}

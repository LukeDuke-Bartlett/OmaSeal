package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/duketopceo/OmaSeal/engine/ui"
)

type RulePolicy string

const (
	PolicyAllow RulePolicy = "ALLOW"
	PolicyDeny  RulePolicy = "DENY"
	PolicyAsk   RulePolicy = "ASK"
)

// ManifestRule is a single robots.txt-style rule for AI agents.
type ManifestRule struct {
	Policy      RulePolicy `json:"policy"`
	Pattern     string     `json:"pattern"`
	Description string     `json:"description"`
}

// Manifest represents the AI access policy manifest.
type Manifest struct {
	Path  string         `json:"path"`
	Rules []ManifestRule `json:"rules"`
}

// ManifestPath returns the path to the ai-manifest.txt file. Reads must not
// create the config dir as a side effect — manifestDir makes it only on write.
func ManifestPath() (string, error) {
	dir := omasealConfigDir()
	if dir == "" {
		return "", fmt.Errorf("cannot resolve config dir")
	}
	return filepath.Join(dir, "ai-manifest.txt"), nil
}

// manifestDir creates the config dir for manifest writes.
func manifestDir() (string, error) {
	path, err := ManifestPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return path, nil
}

// LoadManifest parses the ai-manifest.txt file.
func LoadManifest() (*Manifest, error) {
	path, err := ManifestPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Manifest{Path: path, Rules: nil}, nil
		}
		return nil, err
	}
	defer f.Close()

	rules, err := scanManifestRules(f)
	if err != nil {
		return nil, err
	}
	return &Manifest{Path: path, Rules: rules}, nil
}

// scanManifestRules parses manifest rule lines from any reader — shared by
// LoadManifest and manifest apply's reparse-check of rendered output.
func scanManifestRules(r io.Reader) ([]ManifestRule, error) {
	var rules []ManifestRule
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		policy, pattern, desc, ok := parseRuleLine(line)
		if !ok {
			continue
		}
		rules = append(rules, ManifestRule{
			Policy:      policy,
			Pattern:     pattern,
			Description: desc,
		})
	}

	return rules, scanner.Err()
}

// CheckPolicy determines whether an AI agent is ALLOW, DENY, or ASK for a secret.
func (m *Manifest) CheckPolicy(service, account string) (RulePolicy, string) {
	target := strings.ToLower(service) + "/" + strings.ToLower(account)
	serviceWildcard := strings.ToLower(service) + "/*"

	// 1. Exact match
	for _, r := range m.Rules {
		if strings.EqualFold(r.Pattern, target) {
			return r.Policy, r.Description
		}
	}

	// 2. Service wildcard
	for _, r := range m.Rules {
		if strings.EqualFold(r.Pattern, serviceWildcard) {
			return r.Policy, r.Description
		}
	}

	// 3. Catch-all wildcard
	for _, r := range m.Rules {
		if r.Pattern == "*" || r.Pattern == "*/*" {
			return r.Policy, r.Description
		}
	}

	// Default policy for unspecified items is ASK
	return PolicyAsk, "Unspecified in AI manifest; prompt confirmation required"
}

// Scaffolding helper for init. First substring match wins, so the table is
// ordered most-permissive-guess first; anything unmatched defaults to ASK.
var defaultPolicyTable = []struct {
	substrs []string
	policy  RulePolicy
	desc    string
}{
	{[]string{"openrouter", "perplexity", "kurultai", "claude", "codex", "devin", "openai", "anthropic", "gemini", "groq", "composio"}, PolicyAllow, "%s agent inference and tool execution"},
	{[]string{"hetzner", "tailscale", "github", "cloudflare", "n8n", "shippedit", "aws", "docker", "ssh"}, PolicyAsk, "%s infrastructure and automation access"},
	{[]string{"bank", "schwab", "google", "apple", "uber", "hulu", "starbucks", "termius", "experian", "cleanbrowsing"}, PolicyDeny, "Personal %s credentials (restricted)"},
}

func defaultPolicyFor(service string) (RulePolicy, string) {
	s := strings.ToLower(service)
	for _, row := range defaultPolicyTable {
		for _, sub := range row.substrs {
			if strings.Contains(s, sub) {
				return row.policy, fmt.Sprintf(row.desc, service)
			}
		}
	}
	return PolicyAsk, fmt.Sprintf("%s credential", service)
}

// formatRuleLine renders one rule in the canonical column layout shared by
// manifest init and manifest apply. Patterns containing whitespace are
// quoted — padding must wrap the quoted token, never pad inside the quotes
// (that would change the pattern).
func formatRuleLine(policy RulePolicy, pattern, desc string) string {
	tok := pattern
	if strings.ContainsAny(pattern, " \t") {
		tok = `"` + pattern + `"`
	}
	return fmt.Sprintf("%-6s %-37s - %s", policy, tok, desc)
}

// cutField splits s at the first whitespace run (space OR tab — a
// tab-separated rule like "DENY<TAB>x/y" must still parse). The returned
// tail is already left-trimmed.
func cutField(s string) (head, tail string) {
	i := strings.IndexFunc(s, unicode.IsSpace)
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeftFunc(s[i:], unicode.IsSpace)
}

// parseRuleLine extracts (policy, pattern, description) from one manifest
// line. The pattern is a single whitespace-delimited token, or a
// double-quoted span so names containing spaces survive intact
// (space-splitting silently truncated DENY rules — a dead-rule bypass).
// Everything after the pattern is the description, with an optional " - "
// separator. Returns ok=false for comments, blanks, and lines whose first
// token is not a policy word.
func parseRuleLine(ln string) (RulePolicy, string, string, bool) {
	t := strings.TrimSpace(ln)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", "", "", false
	}
	word, rest := cutField(t)
	var policy RulePolicy
	switch strings.ToUpper(word) {
	case "ALLOW":
		policy = PolicyAllow
	case "DENY":
		policy = PolicyDeny
	case "ASK":
		policy = PolicyAsk
	default:
		return "", "", "", false
	}
	var pattern string
	if strings.HasPrefix(rest, `"`) {
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return "", "", "", false // unterminated quote
		}
		pattern = rest[1 : 1+end]
		rest = strings.TrimLeftFunc(rest[1+end+1:], unicode.IsSpace)
	} else {
		pattern, rest = cutField(rest)
	}
	if pattern == "" {
		return "", "", "", false
	}
	desc := strings.TrimSpace(rest)
	desc = strings.TrimPrefix(desc, "- ")
	desc = strings.TrimSpace(desc)
	return policy, pattern, desc, true
}

// lineRuleToken reports whether a non-comment line's first token parses as a
// policy word at all — used by audit to flag typo/lookalike tokens (e.g.
// Cyrillic homoglyphs) that silently drop the rule.
func lineRuleToken(ln string) (string, bool) {
	t := strings.TrimSpace(ln)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", true // not a rule line at all — nothing to flag
	}
	word, _ := cutField(t)
	_, _, _, ok := parseRuleLine(t)
	return word, ok
}

// GenerateDefaultManifest builds a starter robots.txt manifest from existing
// items and reports the service/account names skipped because they contain
// quote/comment characters that would corrupt a rule line.
func GenerateDefaultManifest(items []Item) (content string, skipped []string) {
	var b strings.Builder
	b.WriteString("# OmaSeal AI Agent Access Manifest (robots.txt format)\n")
	b.WriteString("# Governs AI agent tool access and automated keyring usage.\n")
	b.WriteString("# Scope: enforced on the agent (MCP) channel only. Same-user processes\n")
	b.WriteString("# can still read via `omaseal get` / IPC — DENY is a policy boundary for\n")
	b.WriteString("# wired agents, not confinement against a shell-capable process.\n")
	b.WriteString("#\n")
	b.WriteString("# Policies:\n")
	b.WriteString("#   ALLOW <pattern> - <description>  (Agent may read without biometric/user gate)\n")
	b.WriteString("#   ASK   <pattern> - <description>  (Agent requires user confirmation before access)\n")
	b.WriteString("#   DENY  <pattern> - <description>  (Agent access strictly forbidden)\n")
	b.WriteString("#   Patterns containing spaces must be double-quoted: DENY \"svc/acct name\"\n\n")

	// Group items into Allow, Ask, Deny
	var allows, asks, denies []string
	seen := make(map[string]bool)

	for _, it := range items {
		service, account := sanitizeField(it.Service), sanitizeField(it.Account)
		// Judge the RAW name: sanitizeField already strips newlines, so
		// checking the sanitized value would make the \n\r test dead code.
		// Quotes and '#' would corrupt the rule line; whitespace is fine —
		// formatRuleLine quotes spaced patterns.
		if service == "" || account == "" || strings.ContainsAny(it.Service+it.Account, "\"#\n\r") {
			skipped = append(skipped, it.Service+"/"+it.Account)
			continue
		}
		target := fmt.Sprintf("%s/%s", service, account)
		if seen[target] {
			continue
		}
		seen[target] = true

		policy, desc := defaultPolicyFor(service)
		line := formatRuleLine(policy, target, sanitizeField(desc)) + "\n"

		switch policy {
		case PolicyAllow:
			allows = append(allows, line)
		case PolicyAsk:
			asks = append(asks, line)
		case PolicyDeny:
			denies = append(denies, line)
		}
	}

	b.WriteString("# ── Allowed AI & Agent Tools ──\n")
	for _, l := range allows {
		b.WriteString(l)
	}

	b.WriteString("\n# ── Infrastructure & Automation (Confirmation Required) ──\n")
	for _, l := range asks {
		b.WriteString(l)
	}

	b.WriteString("\n# ── Restricted & Personal Credentials ──\n")
	for _, l := range denies {
		b.WriteString(l)
	}

	if len(skipped) > 0 {
		b.WriteString("\n# Items whose names contain whitespace cannot be expressed as rules;\n")
		b.WriteString("# they are governed only by the fallback policy below.\n")
		for _, s := range skipped {
			fmt.Fprintf(&b, "#   skipped: %s\n", s)
		}
	}

	b.WriteString("\n# Fallback policy for any unlisted credentials\n")
	b.WriteString("ASK    *                                   - Unspecified credentials require confirmation\n")

	return b.String(), skipped
}

// handleManifest implements `omaseal manifest [show|init|check|path]`.
// The manifest governs agent (MCP) access per secret: DENY refuses the call,
// ASK requires an unlocked session even in open mode, ALLOW proceeds.
func handleManifest() {
	jsonOut := hasFlag(os.Args, "--json")

	var subcmd string
	var extraArgs []string
	for _, a := range os.Args[2:] {
		if a == "--json" || a == "--force" || a == "-f" || a == "--yes" || a == "-y" {
			continue
		}
		if strings.HasPrefix(a, "--proposal") {
			continue // value flag, parsed by flagValue
		}
		if subcmd == "" {
			subcmd = a
		} else {
			extraArgs = append(extraArgs, a)
		}
	}
	if subcmd == "" {
		subcmd = "show"
	}

	switch subcmd {
	case "show":
		m, err := LoadManifest()
		if err != nil {
			printError("loading manifest: ", err)
			os.Exit(1)
		}
		if jsonOut {
			b, _ := json.Marshal(m)
			fmt.Println(string(b))
			return
		}
		if len(m.Rules) == 0 {
			fmt.Println("No AI manifest found at", m.Path)
			fmt.Println("Run 'omaseal manifest init' to generate one from existing secrets.")
			return
		}
		rows := make([][]string, 0, len(m.Rules))
		for _, r := range m.Rules {
			rows = append(rows, []string{fmt.Sprint(r.Policy), sanitizeField(r.Pattern), sanitizeField(r.Description)})
		}
		ui.Table(os.Stdout, 2, []string{"POLICY", "PATTERN", "DESCRIPTION"}, rows)

	case "init":
		path, err := manifestDir()
		if err != nil {
			printError("resolving manifest path: ", err)
			os.Exit(1)
		}
		force := hasFlag(os.Args, "--force") || hasFlag(os.Args, "-f")
		if _, err := os.Stat(path); err == nil {
			if !force {
				fmt.Fprintf(os.Stderr, "Manifest already exists at %s (use --force to overwrite)\n", path)
				os.Exit(1)
			}
			// Overwrite regenerates the WHOLE policy — existing DENYs are
			// rebuilt from current keyring contents. A pty-typed "yes" is
			// forgeable; require presence. Headless opt-out: remove the file
			// first, then init (filesystem-level, same as editing it).
			if err := requirePresenceStrict(context.Background(), "overwrite existing AI manifest", "remove the file first, then run `omaseal manifest init`"); err != nil {
				fmt.Fprintf(os.Stderr, "manifest init: %v\n", err)
				os.Exit(1)
			}
		}
		items, err := List("")
		if err != nil {
			printError("listing secrets for manifest: ", err)
			os.Exit(1)
		}
		content, skipped := GenerateDefaultManifest(items)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			printError("writing manifest: ", err)
			os.Exit(1)
		}
		var allow, ask, deny int
		for _, line := range strings.Split(content, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || strings.HasPrefix(line, "#") {
				continue
			}
			switch fields[0] {
			case "ALLOW":
				allow++
			case "ASK":
				ask++
			case "DENY":
				deny++
			}
		}
		fmt.Printf("Initialized AI agent manifest at %s (%d ALLOW / %d ASK / %d DENY rules).\n", path, allow, ask, deny)
		if len(skipped) > 0 {
			fmt.Printf("Note: %d item(s) skipped — names containing quotes, '#' or newlines cannot be written as rules; the fallback ASK * policy governs them.\n", len(skipped))
		}
		fmt.Println("Review and edit the file — it takes effect on the next agent call.")

	case "check":
		service, account, err := argCredentialsLoose(extraArgs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Usage: omaseal manifest check <service> <account>")
			os.Exit(1)
		}
		m, err := LoadManifest()
		if err != nil {
			printError("loading manifest: ", err)
			os.Exit(1)
		}
		policy, desc := m.CheckPolicy(service, account)
		if jsonOut {
			b, _ := json.Marshal(map[string]string{
				"service":     service,
				"account":     account,
				"policy":      string(policy),
				"description": desc,
			})
			fmt.Println(string(b))
			return
		}
		fmt.Printf("%s: %s/%s (%s)\n", policy, sanitizeField(service), sanitizeField(account), sanitizeField(desc))

	case "path":
		p, err := ManifestPath()
		if err != nil {
			printError("getting manifest path: ", err)
			os.Exit(1)
		}
		fmt.Println(p)

	case "audit":
		handleManifestAudit(os.Args[2:], jsonOut)

	case "apply":
		handleManifestApply(extraArgs, hasFlag(os.Args, "--yes") || hasFlag(os.Args, "-y"))

	default:
		fmt.Fprintln(os.Stderr, "Usage: omaseal manifest [show|init|check|path|audit|apply] [--json] [--proposal <path>] [--yes]")
		os.Exit(1)
	}
}

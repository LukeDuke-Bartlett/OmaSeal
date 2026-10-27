package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"unicode"
)

// policyRank orders restrictiveness so "expansion" is a mechanical comparison:
// moving a target up this ladder grants an agent more access.
func policyRank(p RulePolicy) int {
	switch p {
	case PolicyDeny:
		return 0
	case PolicyAsk:
		return 1
	case PolicyAllow:
		return 2
	}
	return 1 // unknown/fallback behaves like ASK
}

// governsJevCredential reports whether a pattern would govern openrouter/* —
// the Jev companion's own credential path. apply hard-rejects these regardless
// of confirmation so the advisor can never move its own leash, directly or via
// a wildcard that covers it.
func governsJevCredential(pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "*" || p == "*/*" {
		return true // covers openrouter/* among everything else
	}
	return p == "openrouter" || strings.HasPrefix(p, "openrouter/")
}

// validProposalFields rejects change fields that could corrupt the manifest's
// space-separated line format or smuggle a second rule inside a rendered line:
// empty or whitespace-bearing patterns, and control characters anywhere a
// field is rendered or displayed.
func validProposalFields(c ProposalChange) bool {
	if c.Pattern == "" || strings.IndexFunc(c.Pattern, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return false
	}
	for _, f := range []string{c.Description, c.Rationale} {
		if strings.IndexFunc(f, unicode.IsControl) >= 0 {
			return false
		}
	}
	return true
}

// patternProbe turns a rule pattern into the CheckPolicy target that exercises
// it: "svc/acct" -> itself, "svc/*" -> (svc, "*"), catch-all -> ("*", "*").
// CheckPolicy's exact-match compares the literal pattern against the target,
// so probing a wildcard with "*" hits the wildcard rule itself.
func patternProbe(pattern string) (service, account string) {
	svc, acct, _ := strings.Cut(pattern, "/")
	if acct == "" {
		acct = "*"
	}
	return svc, acct
}

// effectiveRank returns the restrictiveness rank a rule set gives the probe
// target for pattern — the policy that would actually govern after the change,
// including exposure of broader rules when a specific rule is removed.
func effectiveRank(rules []ManifestRule, pattern string) int {
	svc, acct := patternProbe(pattern)
	p, _ := (&Manifest{Rules: rules}).CheckPolicy(svc, acct)
	return policyRank(p)
}

// applyChangeToRules is the in-memory form of applyChanges: it transforms a
// rule slice the same way applyChanges transforms file lines, so expansion
// classification sees the manifest exactly as it would be written.
func applyChangeToRules(rules []ManifestRule, c ProposalChange) []ManifestRule {
	out := slices.Clone(rules)
	switch c.Action {
	case "remove":
		for i, r := range out {
			if strings.EqualFold(r.Pattern, c.Pattern) {
				return slices.Delete(out, i, i+1)
			}
		}
	case "set":
		for i, r := range out {
			if strings.EqualFold(r.Pattern, c.Pattern) {
				out[i] = ManifestRule{Policy: RulePolicy(strings.ToUpper(c.Policy)), Pattern: c.Pattern, Description: c.Description}
				return out
			}
		}
	case "add":
		out = append(out, ManifestRule{Policy: RulePolicy(strings.ToUpper(c.Policy)), Pattern: c.Pattern, Description: c.Description})
	}
	return out
}

// countPatternRules counts manifest rules sharing a pattern — the targeting
// count add/set/remove validation depends on.
func countPatternRules(m *Manifest, pattern string) int {
	n := 0
	for _, r := range m.Rules {
		if strings.EqualFold(r.Pattern, pattern) {
			n++
		}
	}
	return n
}

// isExpansionChange recomputes whether a change grants more access — the
// proposal's expands_access flag is a display hint and is never trusted.
// Comparison is on effective policy: removing an ASK github/work can expose
// an ALLOW github/* underneath, which is an expansion no identical-pattern
// check would see.
func isExpansionChange(m *Manifest, c ProposalChange) bool {
	return effectiveRank(applyChangeToRules(m.Rules, c), c.Pattern) > effectiveRank(m.Rules, c.Pattern)
}

// isReductionChange reports whether a change removes a grant — annotated
// "reduce" in the render so the human sees the direction of every change.
func isReductionChange(m *Manifest, c ProposalChange) bool {
	return effectiveRank(applyChangeToRules(m.Rules, c), c.Pattern) < effectiveRank(m.Rules, c.Pattern)
}

// validProposalAction gates the change vocabulary apply understands.
func validProposalAction(c ProposalChange) bool {
	switch c.Action {
	case "remove":
		return true
	case "add", "set":
		switch strings.ToUpper(c.Policy) {
		case "ALLOW", "ASK", "DENY":
			return true
		}
	}
	return false
}

// lockManifest holds an exclusive non-blocking flock on the manifest's
// sibling lock file for the whole validate→write span, closing the window
// where a second process could edit between the proposal-hash check and the
// atomic replace. The lock fd is released on process exit either way.
func lockManifest(path string) (func(), error) {
	lf, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lf.Close()
		return nil, fmt.Errorf("another manifest change is in progress: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		lf.Close()
	}, nil
}

// applyChanges rewrites the manifest file's rule lines surgically — comments,
// grouping headers, and blank lines are preserved. Rule order does not affect
// CheckPolicy (exact → wildcard → catch-all passes), so additions append at EOF.
func applyChanges(content string, changes []ProposalChange) string {
	lines := strings.Split(content, "\n")
	// Shared with the parser: quoted patterns and trailing text are handled
	// identically, so apply can match what scanManifestRules read.
	linePattern := func(ln string) (string, bool) {
		_, pattern, _, ok := parseRuleLine(ln)
		return pattern, ok
	}
	for _, c := range changes {
		switch c.Action {
		case "remove":
			for i, ln := range lines {
				if p, ok := linePattern(ln); ok && strings.EqualFold(p, c.Pattern) {
					lines = append(lines[:i], lines[i+1:]...)
					break
				}
			}
		case "set":
			for i, ln := range lines {
				if p, ok := linePattern(ln); ok && strings.EqualFold(p, c.Pattern) {
					lines[i] = formatRuleLine(RulePolicy(strings.ToUpper(c.Policy)), c.Pattern, c.Description)
					break
				}
			}
		case "add":
			line := formatRuleLine(RulePolicy(strings.ToUpper(c.Policy)), c.Pattern, c.Description)
			// Insert before a trailing empty line when present, else append.
			if n := len(lines); n > 0 && strings.TrimSpace(lines[n-1]) == "" {
				lines = append(lines[:n-1], line, "")
			} else {
				lines = append(lines, line)
			}
		}
	}
	return strings.Join(lines, "\n")
}

// handleManifestApply implements `omaseal manifest apply <proposal> [--yes]`.
// It is a human gate: renders parsed changes, refuses manifest drift and
// openrouter/* self-edits, and requires per-item confirmation for every
// capability-expanding change. --yes (or no TTY) applies non-expanding changes
// only and exits nonzero listing the skipped expansions.
func handleManifestApply(args []string, yes bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: omaseal manifest apply <proposal-file> [--yes]")
		os.Exit(1)
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		printError("reading proposal: ", err)
		os.Exit(1)
	}
	var p Proposal
	if err := json.Unmarshal(data, &p); err != nil {
		printError("parsing proposal: ", err)
		os.Exit(1)
	}
	if p.Version != 1 {
		fmt.Fprintf(os.Stderr, "unsupported proposal version %d (expected 1) — regenerate with `omaseal manifest audit --proposal <path>`\n", p.Version)
		os.Exit(1)
	}
	if len(p.Changes) == 0 {
		fmt.Println("proposal contains no changes — nothing to apply")
		return
	}

	// Hold the manifest lock from hash-check through write: without it a
	// concurrent edit between validate and replace makes the hash binding
	// advisory and the accepted changes apply to a stale base.
	manifestPath, err := ManifestPath()
	if err != nil {
		printError("locating manifest: ", err)
		os.Exit(1)
	}
	unlock, err := lockManifest(manifestPath)
	if err != nil {
		printError("locking manifest: ", err)
		os.Exit(1)
	}
	defer unlock()

	m, err := LoadManifest()
	if err != nil {
		printError("loading manifest: ", err)
		os.Exit(1)
	}
	cur, err := manifestFileSHA256(m.Path)
	if err != nil {
		printError("hashing manifest: ", err)
		os.Exit(1)
	}
	if cur != p.ManifestSHA256 {
		fmt.Fprintf(os.Stderr, "manifest changed since this proposal was generated (%s)\nre-run `omaseal manifest audit --proposal <path>` and review the fresh proposal\n", p.GeneratedAt.Format("2006-01-02 15:04"))
		os.Exit(1)
	}

	// Fail closed on anything the change vocabulary doesn't cover, on fields
	// that could smuggle a rule past the render, on ambiguous targets, and on
	// R6: a proposal touching Jev's credential path is rejected wholesale so a
	// bad change can never ride along with safe ones.
	for _, c := range p.Changes {
		if !validProposalAction(c) || !validProposalFields(c) {
			fmt.Fprintf(os.Stderr, "refusing proposal: malformed change (action %q policy %q pattern %q)\n", c.Action, c.Policy, sanitizeField(c.Pattern))
			os.Exit(1)
		}
		if governsJevCredential(c.Pattern) {
			fmt.Fprintf(os.Stderr, "refusing proposal: change to %q would govern openrouter/* (Jev's credential path)\nedit ai-manifest.txt by hand if this is genuinely intended\n", c.Pattern)
			os.Exit(1)
		}
		switch n := countPatternRules(m, c.Pattern); c.Action {
		case "add":
			if n > 0 {
				fmt.Fprintf(os.Stderr, "refusing proposal: `add %s` but %d rule(s) already match that pattern (first match wins — a later rule is dead)\n", c.Pattern, n)
				os.Exit(1)
			}
		case "set", "remove":
			if n == 0 {
				fmt.Fprintf(os.Stderr, "refusing proposal: `%s %s` matches no existing rule\n", c.Action, c.Pattern)
				os.Exit(1)
			}
			if n > 1 {
				fmt.Fprintf(os.Stderr, "refusing proposal: `%s %s` matches %d rules — ambiguous, fix duplicates by hand\n", c.Action, c.Pattern, n)
				os.Exit(1)
			}
		}
	}

	// Render the parsed truth — this is what the human approves, regardless of
	// what the proposal claims about itself.
	fmt.Printf("proposal by %s, generated %s — %d change(s):\n\n", p.Generator, p.GeneratedAt.Format("2006-01-02 15:04"), len(p.Changes))
	expanding := make([]bool, len(p.Changes))
	for i, c := range p.Changes {
		expanding[i] = isExpansionChange(m, c)
		tag := "keep"
		if expanding[i] {
			tag = "EXPAND"
		} else if isReductionChange(m, c) {
			tag = "reduce"
		}
		fmt.Printf("  %d. [%s] %s %s %s\n", i+1, tag, c.Action, strings.ToUpper(c.Policy), c.Pattern)
		if c.Description != "" {
			fmt.Printf("     desc: %s\n", sanitizeField(c.Description))
		}
		if c.Rationale != "" {
			fmt.Printf("     why:  %s\n", sanitizeField(c.Rationale))
		}
	}
	fmt.Println()

	tty := isStdinTTY()
	if !tty && !yes {
		fmt.Fprintln(os.Stderr, "no TTY for review prompts — re-run interactively, or --yes to apply non-expanding changes only")
		os.Exit(1)
	}

	var accepted []ProposalChange
	var acceptedExp []ProposalChange
	var skipped []ProposalChange
	if yes || !tty {
		for i, c := range p.Changes {
			if expanding[i] {
				skipped = append(skipped, c)
			} else {
				accepted = append(accepted, c)
			}
		}
	} else {
		for i, c := range p.Changes {
			if expanding[i] {
				if confirmExplicit(fmt.Sprintf("apply expansion %d: %s %s %s?", i+1, c.Action, strings.ToUpper(c.Policy), c.Pattern)) {
					acceptedExp = append(acceptedExp, c)
				} else {
					skipped = append(skipped, c)
				}
			} else {
				accepted = append(accepted, c)
			}
		}
		if len(accepted) > 0 && !confirm(fmt.Sprintf("Apply %d non-expanding change(s)?", len(accepted))) {
			accepted = nil
		}
	}

	// Expansions widen the policy — a typed "yes" on a pty is forgeable
	// (script(1), expect, piped stdin), so accepted expansions still need
	// proof the local user responded. Failing the check demotes them to
	// skipped; non-expanding changes are unaffected.
	if len(acceptedExp) > 0 {
		reason := fmt.Sprintf("apply %d manifest policy expansion(s)", len(acceptedExp))
		if err := requirePresenceStrict(context.Background(), reason, "edit "+m.Path+" directly"); err != nil {
			fmt.Fprintf(os.Stderr, "expansions refused — %v\n", err)
			skipped = append(skipped, acceptedExp...)
		} else {
			accepted = append(accepted, acceptedExp...)
		}
	}

	if len(accepted) == 0 {
		fmt.Println("no changes accepted")
	} else {
		raw, err := os.ReadFile(m.Path)
		if err != nil && !os.IsNotExist(err) {
			printError("reading manifest: ", err)
			os.Exit(1)
		}
		out := applyChanges(string(raw), accepted)
		// Reparse the rendered file before it replaces the real one: the
		// candidate must parse cleanly — defense-in-depth against any field
		// corruption that slipped past validation.
		if _, err := scanManifestRules(strings.NewReader(out)); err != nil {
			printError("rendered manifest failed reparse — refusing to write: ", err)
			os.Exit(1)
		}
		if err := writeFileMode(m.Path, []byte(out), 0600); err != nil {
			printError("writing manifest: ", err)
			os.Exit(1)
		}
		fmt.Printf("applied %d change(s) to %s\n", len(accepted), m.Path)
	}

	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "\nskipped %d expanding change(s) (need interactive confirmation):\n", len(skipped))
		for _, c := range skipped {
			fmt.Fprintf(os.Stderr, "  - %s %s %s\n", c.Action, strings.ToUpper(c.Policy), c.Pattern)
		}
		os.Exit(1)
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Hermes loads MCP servers from the `mcp_servers:` mapping in
// ~/.hermes/config.yaml (https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference).
// It does not read ~/.hermes/mcp.json, so a JSON entry there is dead config.
//
// config.yaml is a user-owned file full of comments and unrelated settings, so
// this is a line-level edit that touches nothing outside the omaseal entry,
// not a parse-and-rewrite (which would drop comments and reorder keys). The
// only YAML shapes it understands are block mappings, which is what Hermes
// documents; anything else is refused rather than guessed at.

var (
	hermesServersRe = regexp.MustCompile(`^mcp_servers:\s*(#.*)?$`)
	// `mcp_servers: {}` / `null` / `~` — an empty value we can expand.
	hermesEmptyRe = regexp.MustCompile(`^mcp_servers:\s*(\{\s*\}|null|~)\s*(#.*)?$`)
	hermesKeyRe   = regexp.MustCompile(`^mcp_servers:`)
)

// hermesEntry is the omaseal server block: the key indented by ind spaces and
// its fields by ind more, matching the file's own indent unit (a file written
// with four-space indents gets four-space fields).
func hermesEntry(bin string, ind int) []string {
	pad := strings.Repeat(" ", ind)
	inner := pad + strings.Repeat(" ", ind)
	q, _ := json.Marshal(bin) // a JSON string is a valid YAML double-quoted scalar
	return []string{
		pad + "omaseal:",
		inner + "command: " + string(q),
		inner + `args: ["mcp"]`,
	}
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// blankOrComment reports a line that carries no YAML structure.
func blankOrComment(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}

// mergeHermesYAML inserts (or replaces) mcp_servers.omaseal in config.yaml,
// preserving every other byte of the file.
func mergeHermesYAML(configPath, bin string) error {
	data, mode, err := readConfigPreservingMode(configPath)
	if err != nil {
		return err
	}
	out, err := hermesYAMLWith(string(data), bin)
	if err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	return writeFileMode(configPath, []byte(out), mode)
}

// hermesYAMLWith returns existing with the omaseal entry installed.
func hermesYAMLWith(existing, bin string) (string, error) {
	lines := strings.Split(existing, "\n")

	start := -1
	for i, l := range lines {
		if hermesKeyRe.MatchString(l) {
			start = i
			break
		}
	}

	if start < 0 {
		body := strings.TrimRight(existing, "\n")
		block := "mcp_servers:\n" + strings.Join(hermesEntry(bin, 2), "\n") + "\n"
		if body == "" {
			return block, nil
		}
		return body + "\n\n" + block, nil
	}

	switch {
	case hermesEmptyRe.MatchString(lines[start]):
		lines[start] = "mcp_servers:"
	case !hermesServersRe.MatchString(lines[start]):
		return "", fmt.Errorf("mcp_servers is written inline (%q); expand it to a block mapping or add the omaseal server by hand", strings.TrimSpace(lines[start]))
	}

	// The block runs until the next top-level (column 0) non-comment line.
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if !blankOrComment(lines[i]) && indentOf(lines[i]) == 0 {
			end = i
			break
		}
	}

	// Child indent comes from the first real child, defaulting to two spaces.
	ci := 2
	for i := start + 1; i < end; i++ {
		if !blankOrComment(lines[i]) {
			ci = indentOf(lines[i])
			break
		}
	}

	// Drop any previous omaseal entry: its header plus everything indented
	// deeper (blank and comment lines inside it go with it).
	keep := make([]string, 0, len(lines))
	keep = append(keep, lines[:start+1]...)
	for i := start + 1; i < end; i++ {
		if indentOf(lines[i]) == ci && strings.HasPrefix(strings.TrimSpace(lines[i]), "omaseal:") {
			j := i + 1
			for j < end && (blankOrComment(lines[j]) || indentOf(lines[j]) > ci) {
				j++
			}
			// Keep trailing blanks/comments that precede the next sibling.
			for j > i+1 && blankOrComment(lines[j-1]) {
				j--
			}
			i = j - 1
			continue
		}
		keep = append(keep, lines[i])
	}

	// Insert after the last structural line of the block, so blank lines and
	// comments that introduce the next section stay where they were.
	insertAt := len(keep)
	for insertAt > start+1 && blankOrComment(keep[insertAt-1]) {
		insertAt--
	}
	rest := append([]string{}, keep[insertAt:]...)
	out := append(append(append([]string{}, keep[:insertAt]...), hermesEntry(bin, ci)...), rest...)
	out = append(out, lines[end:]...)
	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return res, nil
}

// hermesHasOmaseal reports whether config.yaml already wires omaseal under
// mcp_servers.
func hermesHasOmaseal(data string) bool {
	lines := strings.Split(data, "\n")
	in := false
	ci := -1
	for _, l := range lines {
		if hermesKeyRe.MatchString(l) {
			in, ci = true, -1
			continue
		}
		if !in || blankOrComment(l) {
			continue
		}
		if indentOf(l) == 0 {
			in = false
			continue
		}
		if ci < 0 {
			ci = indentOf(l)
		}
		if indentOf(l) == ci && strings.HasPrefix(strings.TrimSpace(l), "omaseal:") {
			return true
		}
	}
	return false
}

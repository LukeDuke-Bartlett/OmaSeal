package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/duketopceo/OmaSeal/engine/ui"
)

// Config merge strategies for agentSpec.format.
const (
	formatJSON      = "json"
	formatCodexTOML = "toml-codex"
	formatHermesYML = "yaml-hermes"
)

// agentSpec describes where one agent reads its MCP server configuration and
// how to detect that the agent is installed on this machine.
type agentSpec struct {
	name string
	// dirs and files are home-relative paths whose existence marks the agent
	// as installed (e.g. ".claude", ".codex/config.toml").
	dirs  []string
	files []string
	// bins are looked up on PATH as an additional detection signal.
	bins []string
	// globalPath is the home-relative config file written for user-wide MCP.
	globalPath string
	// projectPath is the --dir-relative config file written for repo-local MCP.
	// Empty means the agent has no repo-local config surface.
	projectPath string
	// format selects the merge strategy: formatJSON merges a servers object,
	// formatCodexTOML appends a [mcp_servers.omaseal] table, formatHermesYML
	// edits the mcp_servers mapping of Hermes's config.yaml.
	format string
	// serversKey is the top-level JSON key holding the server map.
	serversKey string
	// entry builds the JSON server entry for this agent.
	entry func(bin string) map[string]any
	// fit is a one-line hint for the deeper integration this harness offers
	// beyond the MCP entry — surfaced in `mcp status` and doctor.
	fit string
}

func stdioEntry(bin string) map[string]any {
	return map[string]any{
		"type":    "stdio",
		"command": bin,
		"args":    []string{"mcp"},
	}
}

func transportEntry(bin string) map[string]any {
	return map[string]any{
		"transport": "stdio",
		"command":   bin,
		"args":      []string{"mcp"},
	}
}

func opencodeEntry(bin string) map[string]any {
	return map[string]any{
		"type":    "local",
		"command": []string{bin, "mcp"},
		"enabled": true,
	}
}

var agentSpecs = []agentSpec{
	{
		name:        "claude",
		dirs:        []string{".claude"},
		files:       []string{".claude.json"},
		bins:        []string{"claude"},
		globalPath:  ".claude.json",
		projectPath: ".mcp.json",
		format:      formatJSON,
		serversKey:  "mcpServers",
		entry:       stdioEntry,
		fit:         "apiKeyHelper can read Claude's key via `omaseal get`; wrap MCP env in `omaseal run`",
	},
	{
		name:        "codex",
		dirs:        []string{".codex"},
		bins:        []string{"codex"},
		globalPath:  filepath.Join(".codex", "config.toml"),
		projectPath: filepath.Join(".codex", "config.toml"),
		format:      formatCodexTOML,
		fit:         "config.toml env is literal-only — wrap servers in `omaseal run -e K=svc/acct --`",
	},
	{
		name:        "cursor",
		dirs:        []string{".cursor"},
		bins:        []string{"cursor"},
		globalPath:  filepath.Join(".cursor", "mcp.json"),
		projectPath: filepath.Join(".cursor", "mcp.json"),
		format:      formatJSON,
		serversKey:  "mcpServers",
		entry:       stdioEntry,
		fit:         "prefer `omaseal run` over ${env:} interpolation — no shell-env dependency",
	},
	{
		name:        "devin",
		dirs:        []string{filepath.Join(".config", "devin"), ".devin"},
		bins:        []string{"devin"},
		globalPath:  filepath.Join(".config", "devin", "mcp_config.json"),
		projectPath: filepath.Join(".devin", "mcp_config.json"),
		format:      formatJSON,
		serversKey:  "mcpServers",
		entry:       transportEntry,
		fit:         "`omaseal run` for local stdio MCPs; cloud Devin uses platform secrets",
	},
	{
		name:        "opencode",
		dirs:        []string{filepath.Join(".config", "opencode")},
		bins:        []string{"opencode"},
		globalPath:  filepath.Join(".config", "opencode", "opencode.json"),
		projectPath: "opencode.json",
		format:      formatJSON,
		serversKey:  "mcp",
		entry:       opencodeEntry,
		fit:         "prefer `omaseal run` over {env:} interpolation in command",
	},
	{
		name:        "agy",
		dirs:        []string{".agy"},
		bins:        []string{"agy", "antigravity"},
		globalPath:  filepath.Join(".agy", "mcp.json"),
		projectPath: filepath.Join(".agy", "mcp.json"),
		format:      formatJSON,
		serversKey:  "mcpServers",
		entry:       stdioEntry,
		fit:         "wrap MCP env in `omaseal run -e K=svc/acct --`",
	},
	{
		name:       "hermes",
		dirs:       []string{".hermes"},
		bins:       []string{"hermes"},
		globalPath: filepath.Join(".hermes", "config.yaml"),
		// Hermes has no repo-local MCP config, and it never reads mcp.json.
		projectPath: "",
		format:      formatHermesYML,
		fit:         "wrap MCP env in `omaseal run -e K=svc/acct --`",
	},
}

// agentAliases maps alternate names to the canonical spec name.
var agentAliases = map[string]string{
	"antigravity": "agy",
	"claude-code": "claude",
}

func findAgentSpec(name string) (agentSpec, bool) {
	if canonical, ok := agentAliases[name]; ok {
		name = canonical
	}
	for _, s := range agentSpecs {
		if s.name == name {
			return s, true
		}
	}
	return agentSpec{}, false
}

// canonicalAgentNames returns spec names in a stable order for output.
func canonicalAgentNames() []string {
	names := make([]string, 0, len(agentSpecs))
	for _, s := range agentSpecs {
		names = append(names, s.name)
	}
	return names
}

// agentDetected reports whether the agent appears to be installed: any marker
// dir/file exists in home, or a known binary is on PATH.
func agentDetected(s agentSpec, home string) bool {
	for _, d := range s.dirs {
		if st, err := os.Stat(filepath.Join(home, d)); err == nil && st.IsDir() {
			return true
		}
	}
	for _, f := range s.files {
		if _, err := os.Stat(filepath.Join(home, f)); err == nil {
			return true
		}
	}
	for _, b := range s.bins {
		if commandExists(b) {
			return true
		}
	}
	return false
}

// detectedAgents returns the names of all agents detected on this machine.
func detectedAgents() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range agentSpecs {
		if agentDetected(s, home) {
			out = append(out, s.name)
		}
	}
	return out
}

// agentConfigTarget resolves the config file to write for an agent. dir == ""
// means the user-level config; otherwise a project-level file under dir.
func agentConfigTarget(s agentSpec, dir string) (string, error) {
	if dir != "" {
		if s.projectPath == "" {
			return "", fmt.Errorf("%s has no project-level MCP config; omit --dir", s.name)
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("resolve --dir: %w", err)
		}
		return filepath.Join(abs, s.projectPath), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot determine user home directory")
	}
	return filepath.Join(home, s.globalPath), nil
}

func handleMCPInstall() {
	if len(os.Args) < 4 {
		mcpInstallUsage()
		os.Exit(1)
	}

	agent := os.Args[3]
	fs := flag.NewFlagSet("mcp-install", flag.ContinueOnError)
	dir := fs.String("dir", "", "Install the project-level MCP config in this directory instead of the user config")
	if err := fs.Parse(os.Args[4:]); err != nil {
		printError("install: ", err)
		mcpInstallUsage()
		os.Exit(1)
	}

	installedPath, err := installMCP(agent, *dir)
	if err != nil {
		printError("install: ", err)
		os.Exit(1)
	}
	fmt.Printf("OmaSeal MCP installed for %s at %s.\n", agent, installedPath)
}

func handleMCPInstallAll() {
	fs := flag.NewFlagSet("mcp-install-all", flag.ContinueOnError)
	dir := fs.String("dir", "", "Install project-level MCP configs in this path instead of user configs")
	if err := fs.Parse(os.Args[3:]); err != nil {
		printError("install-all: ", err)
		mcpInstallAllUsage()
		os.Exit(1)
	}
	if err := installForAgents(canonicalAgentNames(), flagDir(fs, dir)); err != nil {
		printError("install: ", err)
		os.Exit(1)
	}
}

func handleMCPInstallDetected() {
	fs := flag.NewFlagSet("mcp-install-detected", flag.ContinueOnError)
	dir := fs.String("dir", "", "Install project-level MCP configs in this path instead of user configs")
	if err := fs.Parse(os.Args[3:]); err != nil {
		printError("install-detected: ", err)
		mcpInstallAllUsage()
		os.Exit(1)
	}

	targets := map[string]bool{}
	for _, name := range detectedAgents() {
		targets[name] = true
	}
	// The user's assigned defaults and primary agent are always included.
	p := loadAgentPolicyOrDefault()
	for _, name := range p.Agents {
		targets[name] = true
	}
	if p.PrimaryAgent != "" {
		targets[p.PrimaryAgent] = true
	}

	if len(targets) == 0 {
		fmt.Println("No agents detected. Install an agent first, or assign defaults with `omaseal agent defaults <names...>`.")
		return
	}

	if err := installForAgents(slices.Sorted(maps.Keys(targets)), flagDir(fs, dir)); err != nil {
		printError("install: ", err)
		os.Exit(1)
	}
}

func flagDir(fs *flag.FlagSet, dir *string) string {
	targetDir := *dir
	if fs.NArg() > 0 && targetDir == "" {
		targetDir = fs.Arg(0)
	}
	if fs.NArg() > 1 || (fs.NArg() > 0 && *dir != "") {
		fmt.Fprintln(os.Stderr, "error: unexpected positional arguments")
		os.Exit(2)
	}
	return targetDir
}

// installForAgents wires each agent and returns the per-agent failures joined
// so callers (setup) can continue instead of dying mid-flow.
func installForAgents(names []string, dir string) error {
	errs := []string{}
	for _, agent := range names {
		path, err := installMCP(agent, dir)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", agent, err))
		} else {
			fmt.Println("installed:", agent, "->", path)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// mcpAgentStatus is one row of `omaseal mcp status` output.
type mcpAgentStatus struct {
	Name      string `json:"name"`
	Detected  bool   `json:"detected"`
	Installed bool   `json:"installed"`
	Config    string `json:"config"`
	Primary   bool   `json:"primary,omitempty"`
	Default   bool   `json:"default,omitempty"`
	// Fit describes the deeper integration this harness offers beyond the
	// MCP entry (empty = the standard `omaseal run` wrapper).
	Fit string `json:"fit,omitempty"`
}

func mcpStatusRows() []mcpAgentStatus {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil // relative spec paths would stat against CWD and false-positive
	}
	p := loadAgentPolicyOrDefault()
	defaults := map[string]bool{}
	for _, n := range p.Agents {
		defaults[n] = true
	}
	rows := make([]mcpAgentStatus, 0, len(agentSpecs))
	for _, s := range agentSpecs {
		path, err := agentConfigTarget(s, "")
		if err != nil {
			continue
		}
		rows = append(rows, mcpAgentStatus{
			Name:      s.name,
			Detected:  agentDetected(s, home),
			Installed: mcpInstalledAt(s, path),
			Config:    path,
			Primary:   p.PrimaryAgent == s.name,
			Default:   defaults[s.name],
			Fit:       s.fit,
		})
	}
	return rows
}

func handleMCPStatus() {
	rows := mcpStatusRows()
	if hasFlag(os.Args, "--json") {
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(b))
		return
	}
	if ui.Fancy(os.Stdout) {
		trows := make([][]string, 0, len(rows))
		for _, r := range rows {
			trows = append(trows, []string{r.Name, yesNo(r.Detected), yesNo(r.Installed), mcpRole(r), r.Config})
		}
		ui.Table(os.Stdout, 2, []string{"AGENT", "DETECTED", "INSTALLED", "ROLE", "CONFIG"}, trows)
	} else {
		fmt.Printf("%-10s %-9s %-9s %-7s %s\n", "AGENT", "DETECTED", "INSTALLED", "ROLE", "CONFIG")
		for _, r := range rows {
			fmt.Printf("%-10s %-9s %-9s %-7s %s\n", r.Name, yesNo(r.Detected), yesNo(r.Installed), mcpRole(r), r.Config)
		}
	}
	printed := false
	for _, r := range rows {
		if r.Detected && r.Fit != "" {
			if !printed {
				fmt.Println("\ndeeper fit:")
				printed = true
			}
			fmt.Printf("  %-10s %s\n", r.Name, r.Fit)
		}
	}
}

func mcpRole(r mcpAgentStatus) string {
	switch {
	case r.Primary:
		return "primary"
	case r.Default:
		return "default"
	}
	return ""
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

// mcpInstalledAt reports whether the config file at path already contains an
// omaseal server entry.
func mcpInstalledAt(s agentSpec, path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if s.format == formatCodexTOML {
		return codexMCPRe.MatchString(string(data))
	}
	if s.format == formatHermesYML {
		return hermesHasOmaseal(string(data))
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	raw, ok := cfg[s.serversKey]
	if !ok {
		return false
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(raw, &servers); err != nil {
		return false
	}
	_, ok = servers["omaseal"]
	return ok
}

func installMCP(agent, dir string) (string, error) {
	spec, ok := findAgentSpec(agent)
	if !ok {
		return "", unknownAgentError(agent)
	}

	self, err := os.Executable()
	if err != nil {
		self = "omaseal"
	}

	configPath, err := agentConfigTarget(spec, dir)
	if err != nil {
		return "", err
	}

	if spec.format == formatCodexTOML {
		if err := mergeCodexTOML(configPath, self); err != nil {
			return "", err
		}
		return configPath, nil
	}

	if spec.format == formatHermesYML {
		if err := mergeHermesYAML(configPath, self); err != nil {
			return "", err
		}
		return configPath, nil
	}

	if err := mergeJSONConfig(configPath, spec, self); err != nil {
		return "", err
	}
	return configPath, nil
}

// readConfigPreservingMode returns the file's contents and permission bits in
// one open. A missing file yields nil data and 0600 so a freshly created
// user-level config is never world-readable on a traversable path.
func readConfigPreservingMode(path string) (data []byte, mode os.FileMode, err error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0o600, nil
		}
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	data, err = io.ReadAll(f)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	return data, st.Mode().Perm(), nil
}

// writeFileMode writes atomically: a temp file in the same directory is
// fsynced and renamed over the target, so a crash mid-write can never leave
// a truncated config another tool owns. A symlinked target (dotfile managers)
// is resolved first so the rename replaces the real file, not the link.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			path = real
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".omaseal-*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// mergeJSONConfig inserts (or replaces) the omaseal server entry while
// preserving every other top-level key and server in the file.
func mergeJSONConfig(configPath string, spec agentSpec, bin string) error {
	data, mode, err := readConfigPreservingMode(configPath)
	if err != nil {
		return err
	}
	rawConfig := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &rawConfig); err != nil {
			return fmt.Errorf("parse %s: %w", configPath, err)
		}
	}

	servers := map[string]any{}
	if raw, ok := rawConfig[spec.serversKey]; ok && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return fmt.Errorf("parse %s %s: %w", configPath, spec.serversKey, err)
		}
		if servers == nil {
			servers = map[string]any{}
		}
	}
	servers["omaseal"] = spec.entry(bin)

	out := map[string]any{}
	for k, v := range rawConfig {
		if k == spec.serversKey {
			out[k] = servers
		} else {
			out[k] = v
		}
	}
	if _, ok := out[spec.serversKey]; !ok {
		out[spec.serversKey] = servers
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal mcp config: %w", err)
	}
	return writeFileMode(configPath, b, mode)
}

// codexMCPRe matches an existing [mcp_servers.omaseal] table header in TOML.
// The earlier mcpServers spelling is also matched so installs repair it.
var codexMCPRe = regexp.MustCompile(`(?m)^\s*\[\s*mcp(?:_s|S)ervers\.omaseal\s*\]`)

// mergeCodexTOML writes omaseal into ~/.codex/config.toml as a
// [mcp_servers.omaseal] table, replacing any previous omaseal table and
// preserving all other content.
func mergeCodexTOML(configPath, bin string) error {
	data, mode, err := readConfigPreservingMode(configPath)
	if err != nil {
		return err
	}
	existing := string(data)

	// Cut a previous [mcpServers.omaseal] table: from its header line to the
	// next table header or EOF.
	lines := strings.Split(existing, "\n")
	kept := lines[:0]
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			if codexMCPRe.MatchString(line) {
				skipping = true
				continue
			}
			skipping = false
		}
		if !skipping {
			kept = append(kept, line)
		}
	}
	cleaned := strings.TrimRight(strings.Join(kept, "\n"), "\n")

	block := fmt.Sprintf("[mcp_servers.omaseal]\ncommand = %q\nargs = [\"mcp\"]\n", bin)
	out := block
	if cleaned != "" {
		out = cleaned + "\n\n" + block
	}

	return writeFileMode(configPath, []byte(out), mode)
}

func mcpInstallUsage() {
	fmt.Fprintf(os.Stderr, "usage: omaseal mcp install <%s> [--dir <path>]\n", strings.Join(canonicalAgentNames(), "|"))
	fmt.Fprintln(os.Stderr, "       --dir .   writes the project-level MCP config in the current repo")
	fmt.Fprintln(os.Stderr, "       aliases:  antigravity -> agy, claude-code -> claude")
}

func mcpInstallAllUsage() {
	fmt.Fprintln(os.Stderr, "usage: omaseal mcp install-all [--dir <path>]")
	fmt.Fprintln(os.Stderr, "       omaseal mcp install-detected [--dir <path>]")
	fmt.Fprintln(os.Stderr, "       omaseal mcp status [--json]")
	fmt.Fprintln(os.Stderr, "  install-all writes every known agent; install-detected writes only")
	fmt.Fprintln(os.Stderr, "  agents found on this machine plus your defaults and primary agent.")
}

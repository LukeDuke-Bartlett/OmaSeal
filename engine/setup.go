package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/duketopceo/OmaSeal/engine/ui"
)

// runSetup is the guided onboarding path: verify the environment, show which
// agents are detected and already wired, offer to install MCP config for the
// rest, and set a primary agent. `omaseal setup --yes` skips the prompts so
// installers and dotfile scripts can run it unattended.
func runSetup() {
	yes := hasFlag(os.Args, "--yes") || hasFlag(os.Args, "-y")

	ui.Banner(os.Stderr, version, target())
	fmt.Fprintln(os.Stderr, "Running doctor first...")
	results := doctorChecks()
	printDoctorResults(results)

	fmt.Fprintln(os.Stderr)
	if ui.Fancy(os.Stderr) {
		ui.Heading(os.Stderr, "Agents")
	} else {
		fmt.Fprintln(os.Stderr, "=== Agents ===")
	}
	rows := mcpStatusRows()
	detected := []mcpAgentStatus{}
	for _, r := range rows {
		fmt.Fprintf(os.Stderr, "  %-10s detected:%-4s installed:%-4s %s\n",
			r.Name, yesNo(r.Detected), yesNo(r.Installed), r.Config)
		if r.Detected {
			detected = append(detected, r)
		}
	}
	if len(detected) == 0 {
		fmt.Fprintln(os.Stderr, "  no supported agents detected yet")
	}

	p := loadAgentPolicyOrDefault()
	if p.PrimaryAgent != "" {
		fmt.Fprintf(os.Stderr, "  primary agent: %s\n", p.PrimaryAgent)
	}
	if len(p.Agents) > 0 {
		fmt.Fprintf(os.Stderr, "  defaults:      %s\n", strings.Join(p.Agents, ", "))
	}

	if isStdinTTY() || yes {
		maybeInstallDetected(detected, yes)
		maybeSetPrimary(rows, p, yes)
		maybeOfferJev(yes)
		maybeOfferClaudeKeyHelper(detected, yes)
	} else {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Run `omaseal setup --yes` to auto-wire every detected agent,")
		fmt.Fprintln(os.Stderr, "or `omaseal mcp install-detected` / `omaseal mcp install <agent>`.")
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "=== Omarchy / Quickshell ===")
	fmt.Fprintln(os.Stderr, "The plugin is ready. Make sure it is in `~/.config/omarchy/plugins/io.github.duketopceo.omaseal` or installed via AUR.")
	fmt.Fprintln(os.Stderr, "Run `omarchy-restart-shell` after enabling.")

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "=== Shell PATH ===")
	bin, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot locate the running binary. Run `omaseal doctor` after installation.")
	} else {
		dir := filepath.Dir(bin)
		if dirOnPATH(dir) {
			fmt.Fprintf(os.Stderr, "%s is on PATH.\n", dir)
		} else {
			fmt.Fprintf(os.Stderr, "Add to `~/.bashrc` or `~/.zshrc`:\n  export PATH=\"%s:$PATH\"\n", dir)
		}
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "=== Verify ===")
	// The round-trip may block on a keyring unlock prompt; bound it so a
	// headless or unattended setup cannot hang forever.
	testCh := make(chan error, 1)
	go func() { testCh <- selftestRoundTrip() }()
	select {
	case err := <-testCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "selftest failed: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "selftest ok: set/get/delete round-trip passed")
		}
	case <-time.After(30 * time.Second):
		fmt.Fprintln(os.Stderr, "selftest timed out (keyring may be locked) — run `omaseal selftest` after unlocking")
		// The abandoned round-trip may still land its probe Set after the
		// prompt resolves; remove it once it would have finished.
		go func() {
			time.Sleep(60 * time.Second)
			_ = Delete("omaseal-selftest", "selftest")
		}()
	}
	fmt.Fprintln(os.Stderr, "Agents pick up OmaSeal on their next start; the MCP server tells them to use it.")
	if loadAgentPolicyOrDefault().Mode == "open" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Agent mode is `open` — every wired agent can read secrets freely.")
		fmt.Fprintln(os.Stderr, "Run `omaseal agent mode ask` to gate agent access behind a session unlock.")
	}

	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("fprintd-verify"); err == nil {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "=== Fingerprint ===")
			fmt.Fprintln(os.Stderr, "Enroll a finger with `fprintd-enroll` to enable biometric reveal.")
		}
		if p := loadAgentPolicyOrDefault(); p.Mode == "ask" {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			mech := presenceMechanism(ctx, p, fprintdUsableFunc(ctx))
			cancel()
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "Presence gate for `agent unlock`: %s\n", mech)
			if strings.HasPrefix(mech, "none") {
				fmt.Fprintln(os.Stderr, "  Install fprintd or a GUI prompter (pinentry/zenity), or run `omaseal agent mode ask --ungated` to opt out deliberately.")
			}
		}
	}
}

// maybeInstallDetected wires OmaSeal into every detected agent that does not
// already have it. On a TTY it asks once (default: no); with --yes it just does it.
func maybeInstallDetected(detected []mcpAgentStatus, yes bool) {
	todo := []string{}
	for _, r := range detected {
		if !r.Installed {
			todo = append(todo, r.Name)
		}
	}
	if len(todo) == 0 {
		return
	}

	fmt.Fprintln(os.Stderr)
	if !yes && !confirm(fmt.Sprintf("Install OmaSeal MCP for detected agents (%s)?", strings.Join(todo, ", "))) {
		return
	}
	// Report failures but keep going — setup continues to primary-agent
	// selection and the remaining sections.
	if err := installForAgents(todo, ""); err != nil {
		fmt.Fprintf(os.Stderr, "  some agents failed to install: %v\n", err)
	}
}

// maybeOfferClaudeKeyHelper offers to point Claude Code's apiKeyHelper at
// `omaseal get` so Claude's own API key is read from the keyring at call time
// instead of living in a file. It only ever prompts interactively — under
// --yes a hint is printed, since redirecting a harness's auth source is a
// deliberate choice, not part of unattended MCP wiring.
func maybeOfferClaudeKeyHelper(detected []mcpAgentStatus, yes bool) {
	claudeFound := false
	for _, r := range detected {
		if r.Name == "claude" {
			claudeFound = true
		}
	}
	if !claudeFound {
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	// No offer without a stored key: pointing Claude's auth at a secret that
	// does not exist produces a helper that always fails.
	items, err := List("anthropic")
	if err != nil || len(items) == 0 {
		fmt.Fprintln(os.Stderr, "  no anthropic key in the keyring yet — run `omaseal set anthropic <account>` first, then re-run setup for the apiKeyHelper offer")
		return
	}
	self, err := os.Executable()
	if err != nil {
		self = "omaseal"
	}
	// apiKeyHelper is executed via shell — every component is %q-quoted.
	helper := fmt.Sprintf("%q get %q %q", self, "anthropic", items[0].Account)

	data, mode, err := readConfigPreservingMode(settingsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not read %s: %v\n", settingsPath, err)
		return
	}
	settings := map[string]any{}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &settings); err != nil {
			fmt.Fprintf(os.Stderr, "  could not parse %s: %v\n", settingsPath, err)
			return
		}
	}
	if cur, ok := settings["apiKeyHelper"]; ok {
		if cur == helper {
			fmt.Fprintln(os.Stderr, "  claude apiKeyHelper already points at omaseal")
		} else {
			fmt.Fprintf(os.Stderr, "  claude apiKeyHelper is set to %q — leaving it alone\n", cur)
		}
		return
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  claude detected: apiKeyHelper can read your API key via\n    %q\n", helper)
	fmt.Fprintf(os.Stderr, "    (reads anthropic/%s — the key never touches a file)\n", items[0].Account)
	if yes || !confirm("Set claude apiKeyHelper to that helper in ~/.claude/settings.json?") {
		if yes {
			fmt.Fprintln(os.Stderr, "  skipped under --yes: add `\"apiKeyHelper\": \""+helper+"\"` to ~/.claude/settings.json to enable")
		}
		return
	}

	settings["apiKeyHelper"] = helper
	b, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not marshal settings: %v\n", err)
		return
	}
	if err := writeFileMode(settingsPath, b, mode); err != nil {
		fmt.Fprintf(os.Stderr, "  could not write %s: %v\n", settingsPath, err)
		return
	}
	fmt.Fprintf(os.Stderr, "  wrote apiKeyHelper to %s\n", settingsPath)
}

// setupReader is shared across prompts so input buffered by one confirm is
// not lost to the next.
var setupReader = bufio.NewReader(os.Stdin)

// confirm asks once and returns true only on an explicit yes — the default
// answer is No. See ui.Confirm for the interactive and piped paths.
func confirm(question string) bool {
	return ui.Confirm(question, setupReader)
}

// maybeSetPrimary suggests a primary agent when none is configured. On a TTY
// it asks once; with --yes it picks the first detected agent automatically.
func maybeSetPrimary(rows []mcpAgentStatus, p AgentPolicy, yes bool) {
	if p.PrimaryAgent != "" {
		return
	}
	var firstDetected string
	for _, r := range rows {
		if r.Detected {
			firstDetected = r.Name
			break
		}
	}
	if firstDetected == "" {
		return
	}

	fmt.Fprintln(os.Stderr)
	if !yes && !confirm(fmt.Sprintf("Set %s as your primary agent?", firstDetected)) {
		return
	}
	if err := SetPrimaryAgent(firstDetected); err != nil {
		fmt.Fprintf(os.Stderr, "  could not set primary agent: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "  primary agent: %s\n", firstDetected)
}

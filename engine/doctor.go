package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type checkResult struct {
	name    string
	ok      bool
	message string
	// optional checks degrade to a warning instead of failing the doctor run.
	optional bool
}

func handleDoctor() {
	for _, a := range os.Args[2:] {
		if a == "--json" {
			runDoctorJSON()
			return
		}
	}
	runDoctor()
}

func runDoctorJSON() {
	emitCheckJSON(doctorChecks(), "omaseal setup")
}

// emitCheckJSON renders check results in the shared ping/doctor JSON shape.
func emitCheckJSON(results []checkResult, help string) {
	checks, ok := toPingChecks(results)
	res := pingResult{
		Version: version,
		Commit:  commit,
		Target:  target(),
		Ok:      ok,
		Checks:  checks,
		Help:    help,
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error marshaling check result:", err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}

// doctorChecks runs every check concurrently — each is an independent probe
// and several spawn subprocesses with multi-second timeouts, so serial runs
// cost the sum of all timeouts instead of the slowest one.
func doctorChecks() []checkResult {
	checks := []func() checkResult{
		checkBinary,
		checkBackend,
		checkSecretService,
		checkKeyringEncryption,
		checkFprintd,
		checkPresenceGate,
		checkOnePassword,
		checkBitwarden,
		checkGUIPrompt,
		checkPath,
		checkJev,
		checkAgentFit,
		checkLogChain,
		checkFilePerms,
	}
	results := make([]checkResult, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c()
		}()
	}
	wg.Wait()
	return results
}

// toPingChecks converts check results to the JSON shape and reports whether
// all required (non-optional) checks passed.
func toPingChecks(results []checkResult) ([]pingCheck, bool) {
	checks := make([]pingCheck, len(results))
	ok := true
	for i, r := range results {
		checks[i] = pingCheck{Name: r.name, Ok: r.ok, Optional: r.optional, Message: r.message}
		if !r.ok && !r.optional {
			ok = false
		}
	}
	return checks, ok
}

func printDoctorResults(results []checkResult) bool {
	ok := true
	for _, r := range results {
		mark := "ok"
		if !r.ok {
			if r.optional {
				mark = "warn"
			} else {
				mark = "FAIL"
				ok = false
			}
		}
		fmt.Fprintf(os.Stderr, "%-18s %s\n", mark, r.name)
		if r.message != "" {
			for _, line := range strings.Split(r.message, "\n") {
				fmt.Fprintf(os.Stderr, "                   %s\n", line)
			}
		}
	}
	return ok
}

func runDoctor() {
	results := doctorChecks()
	ok := printDoctorResults(results)
	if !ok {
		fmt.Fprintln(os.Stderr, "\nSome required checks failed. Run `omaseal setup` for next steps.")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "\nAll required checks passed. OmaSeal is ready to use.")
}

func checkBinary() checkResult {
	return checkResult{name: "binary", ok: true, message: versionInfo()}
}

func versionInfo() string {
	return fmt.Sprintf("omaseal %s (%s) %s", version, commit, target())
}

// checkBackend reports the configured backend and, for native, whether the
// store is initialized and a session window is live. Informational — an
// uninitialized native store degrades to a warning, not a doctor failure.
func checkBackend() checkResult {
	cfg, err := loadConfig()
	if err != nil {
		return checkResult{name: "backend", ok: false, optional: true,
			message: fmt.Sprintf("cannot read %s: %v", omasealConfigPath(), err)}
	}
	if cfg.Backend != "native" {
		return checkResult{name: "backend", ok: true, optional: true,
			message: "secretservice — gnome-keyring login collection"}
	}
	ns := newNativeStore()
	if _, err := os.Stat(filepath.Join(ns.dir, nativeIdentityFile)); err != nil {
		return checkResult{name: "backend", ok: false, optional: true,
			message: "native — not initialized (run `omaseal migrate` or `omaseal get` in a terminal)"}
	}
	msg := "native — age-encrypted store"
	raw, err := os.ReadFile(filepath.Join(ns.runtimeDir, nativeSessJSONFile))
	if err != nil {
		msg += ", locked"
	} else {
		var sess nativeSession
		switch {
		case json.Unmarshal(raw, &sess) != nil || time.Now().Unix() > sess.Expires:
			msg += ", session expired"
		case ns.loadSession() != nil:
			msg += ", locked"
		default:
			msg += ", session live"
		}
	}
	return checkResult{name: "backend", ok: true, optional: true, message: msg}
}

func checkSecretService() checkResult {
	// On backend: native the daemon is optional infrastructure — needed only
	// for `omaseal migrate` and the secretservice rollback, not for reads.
	cfg, cfgErr := loadConfig()
	nativeBackend := cfgErr == nil && cfg.Backend == "native"
	degraded := func(msg string) checkResult {
		return checkResult{name: "secret-service", ok: !nativeBackend, optional: nativeBackend,
			message: msg}
	}

	// OmaSeal itself may own the name — that's the provider working, not a
	// missing keyring. Check ownership before diagnosing gnome-keyring.
	if conn, err := svcConnect(""); err == nil {
		defer func() { _ = conn.Close() }()
		if ours, owner, _ := svcOwnerIsOurs(conn); ours {
			return checkResult{name: "secret-service", ok: true,
				message: "omaseal provider owns org.freedesktop.secrets (" + owner + ")"}
		}
	}

	if !commandExists("gnome-keyring-daemon") {
		if nativeBackend {
			return degraded("backend is native — gnome-keyring not needed (needed only for `omaseal migrate` / secretservice rollback)")
		}
		return checkResult{
			name: "secret-service",
			ok:   false,
			message: "`gnome-keyring-daemon` not found.\n" +
				"  - Install `gnome-keyring` and `libsecret` from your package manager.",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ps", "-e").Output()
	if err == nil && containsLine(string(out), "gnome-keyring-d") {
		return checkResult{name: "secret-service", ok: true, message: "gnome-keyring-daemon is running"}
	}

	if nativeBackend {
		return degraded("gnome-keyring-daemon not running — harmless on backend: native (needed only for `omaseal migrate` / secretservice rollback)")
	}
	return checkResult{
		name: "secret-service",
		ok:   false,
		message: "`gnome-keyring-daemon` is installed but not running.\n" +
			"  - On Omarchy, the keyring is normally started by the session.\n" +
			"  - Try `gnome-keyring-daemon --start --daemonize` or a shell restart.",
	}
}

func containsLine(text, needle string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

// keyringsDir returns the directory holding gnome-keyring *.keyring files.
func keyringsDir() string {
	if xdg := svcXDGDir("XDG_DATA_HOME", ".local", "share"); xdg != "" {
		return filepath.Join(xdg, "keyrings")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "keyrings")
}

// countPlainSecrets scans gnome-keyring .keyring content for `secret=` values
// stored as printable text. A password-protected keyring writes the secret as
// an encrypted binary blob; an empty-password keyring (common on autologin
// setups where no password reaches PAM) writes the literal secret value.
// Returns (plaintext count, total secrets seen).
func countPlainSecrets(data []byte) (plain, total int) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("secret=")) {
			continue
		}
		v := bytes.TrimSpace(line[len("secret="):])
		if len(v) == 0 {
			continue
		}
		total++
		if bytes.IndexFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0 {
			plain++
		}
	}
	return plain, total
}

// checkKeyringEncryption verifies secrets are not stored plaintext on disk.
// OmaSeal enforces its manifest policy on the Secret Service API path; a
// plaintext keyring file bypasses that policy entirely for anyone who can
// read the file, so this surfaces as a loud warning even though functionally
// everything still works.
func checkKeyringEncryption() checkResult {
	dir := keyringsDir()
	if dir == "" {
		return checkResult{name: "keyring-encryption", ok: true, optional: true,
			message: "cannot determine keyring directory"}
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.keyring"))
	if err != nil || len(files) == 0 {
		return checkResult{name: "keyring-encryption", ok: true, optional: true,
			message: "no keyring files yet — nothing stored"}
	}
	var plain, total int
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		p, t := countPlainSecrets(data)
		plain += p
		total += t
	}
	if plain == 0 {
		return checkResult{name: "keyring-encryption", ok: true,
			message: "keyring secrets are encrypted at rest"}
	}
	return checkResult{
		name:     "keyring-encryption",
		ok:       false,
		optional: true,
		message: fmt.Sprintf("%d/%d stored secrets are PLAINTEXT on disk (%s)\n", plain, total, dir) +
			"  - The keyring has an empty password — common on autologin setups where no password reaches PAM.\n" +
			"  - Fix: `omaseal keyring migrate` (graphical session required — the daemon prompts for the new password).\n" +
			"  - Use your login password so PAM auto-unlocks; disable autologin or it will prompt once per session.\n" +
			"  - Note: full-disk encryption still protects the file when powered off; this gap is for local readers while running.",
	}
}

func checkFprintd() checkResult {
	if !commandExists("fprintd") {
		return checkResult{
			name:     "fprintd",
			ok:       false,
			optional: true,
			message: "`fprintd` is not installed.\n" +
				"  - `reveal` will fall through without a fingerprint gate.\n" +
				"  - Install and enable `fprintd` and run `fprintd-enroll` to enable biometric gating.",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	if err := fprintdAvailable(ctx); err != nil {
		return checkResult{
			name:     "fprintd",
			ok:       false,
			optional: true,
			message: err.Error() + "\n" +
				"  - `reveal` will fall through without a fingerprint gate.\n" +
				"  - Start `fprintd.service`, run `fprintd-enroll`, and try again.",
		}
	}

	return checkResult{name: "fprintd", ok: true, message: "fprintd is available and has an enrolled device"}
}

// checkPresenceGate verifies that ask mode has a user-presence mechanism —
// what makes `omaseal agent unlock` a human-gated action rather than a
// self-serve one. It names the mechanism found, or warns with remediation.
func checkPresenceGate() checkResult {
	p := loadAgentPolicyOrDefault()
	if p.Mode != "ask" {
		return checkResult{name: "presence-gate", ok: true, message: fmt.Sprintf("agent mode is %s — presence gate not required", p.Mode)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if fprintdUsableFunc(ctx) {
		return checkResult{name: "presence-gate", ok: true, message: "fingerprint reader gates `omaseal agent unlock`"}
	}
	if graphicalSession() {
		if prompter, err := selectGUIPrompter(ctx); err == nil {
			return checkResult{name: "presence-gate", ok: true, message: fmt.Sprintf("GUI confirm (%s) gates `omaseal agent unlock`", prompter.name())}
		}
	}
	if p.AllowUngated {
		return checkResult{name: "presence-gate", ok: false, optional: true, message: "ask mode is running ungated (allow_ungated set).\n" +
			"  - `omaseal agent unlock` will not ask for user presence — any local process can open a session.\n" +
			"  - Re-gate with `omaseal agent mode ask`."}
	}
	return checkResult{name: "presence-gate", ok: false, optional: true, message: "no user-presence mechanism for `omaseal agent unlock` — unlock will fail closed.\n" +
		"  - Enroll a fingerprint (fprintd-enroll), or install pinentry/zenity for a GUI confirm dialog.\n" +
		"  - Deliberate opt-out for headless machines: `omaseal agent mode ask --ungated`."}
}

func checkOnePassword() checkResult {
	if !commandExists("op") {
		return checkResult{
			name:     "1password (op)",
			ok:       false,
			optional: true,
			message: "`op` CLI not found.\n" +
				"  - Install the 1Password CLI and run `op signin` to enable `omaseal resolve` / `import 1password`.",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "op", "vault", "list", "--format=json").Output()
	if err == nil && len(bytes.TrimSpace(out)) > 0 {
		return checkResult{name: "1password (op)", ok: true, message: "`op` CLI found and authenticated"}
	}

	return checkResult{
		name:     "1password (op)",
		ok:       false,
		optional: true,
		message: "`op` CLI is installed but not signed in.\n" +
			"  - Run `op signin` to enable `omaseal resolve` / `import 1password`.",
	}
}

func checkBitwarden() checkResult {
	if !commandExists("bw") {
		return checkResult{
			name:     "bitwarden (bw)",
			ok:       false,
			optional: true,
			message: "`bw` CLI not found.\n" +
				"  - Install the Bitwarden CLI and run `bw login` to enable `omaseal resolve` / `import bitwarden`.",
		}
	}
	if os.Getenv("BW_SESSION") != "" {
		return checkResult{name: "bitwarden (bw)", ok: true, message: "`bw` CLI found and BW_SESSION is set"}
	}
	return checkResult{
		name:     "bitwarden (bw)",
		ok:       false,
		optional: true,
		message: "`bw` CLI found but `BW_SESSION` is not set.\n" +
			"  - Run `bw login`, then use a command-scoped session:\n" +
			"    `BW_SESSION=\"$(bw unlock --raw)\" omaseal resolve <service> <account>` or `omaseal import bitwarden`.",
	}
}

// checkGUIPrompt reports the effective masked graphical prompter so a headless
// `omaseal resolve` has somewhere to ask. It is optional: no prompter only
// limits prompting, never the keyring itself.
func checkGUIPrompt() checkResult {
	if !graphicalSession() {
		return checkResult{
			name:     "gui-prompt",
			ok:       false,
			optional: true,
			message: "No graphical session (WAYLAND_DISPLAY/DISPLAY unset).\n" +
				"  - Headless `omaseal resolve` prompts need a TTY or a graphical session.",
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := selectGUIPrompter(ctx)
	if errors.Is(err, errGUIDisabled) {
		return checkResult{name: "gui-prompt", ok: true, optional: true, message: "disabled by OMASEAL_GUI_PROMPT=off"}
	}
	if err != nil {
		return checkResult{
			name:     "gui-prompt",
			ok:       false,
			optional: true,
			message: "No usable masked graphical prompter: " + err.Error() + "\n" +
				"  - Install `pinentry` with a GUI backend or `zenity` for headless `omaseal resolve` prompts.\n" +
				"  - `OMASEAL_GUI_PROMPT=pinentry|zenity|off` overrides prompter selection.",
		}
	}
	return checkResult{name: "gui-prompt", ok: true, optional: true, message: "graphical prompt via " + p.name()}
}

func checkPath() checkResult {
	self, err := os.Executable()
	if err != nil {
		return checkResult{name: "PATH", ok: false, message: "Cannot locate the running binary"}
	}
	dir := filepath.Dir(self)
	if dirOnPATH(dir) {
		return checkResult{name: "PATH", ok: true, message: fmt.Sprintf("`%s` is on PATH", dir)}
	}
	return checkResult{
		name:    "PATH",
		ok:      false,
		message: fmt.Sprintf("`%s` is not on your PATH.\n  - Add `export PATH=\"%s:$PATH\"` to your shell profile.", dir, dir),
	}
}

// checkAgentFit reports which known agent harnesses are installed and how
// deeply OmaSeal can integrate — informational, never fails.
func checkAgentFit() checkResult {
	names := detectedAgents()
	if len(names) == 0 {
		return checkResult{name: "agent-fit", ok: true, optional: true,
			message: "no known agent harnesses detected"}
	}
	var hints []string
	for _, n := range names {
		if s, ok := findAgentSpec(n); ok && s.fit != "" {
			hints = append(hints, fmt.Sprintf("%s: %s", n, s.fit))
		}
	}
	return checkResult{name: "agent-fit", ok: true, optional: true,
		message: fmt.Sprintf("detected: %s\n  - wire MCP: `omaseal mcp install-detected`\n  - %s\n  - details: docs/harness-fit.md",
			strings.Join(names, ", "), strings.Join(hints, "\n  - "))}
}

// checkLogChain verifies the audit log's hash chain — the forensic record
// behind `omaseal stats` and `logs`. A tamper verdict is a hard FAIL:
// integrity of the audit trail is exactly what doctor exists to assess.
func checkLogChain() checkResult {
	logPath := LogPath()
	rep, err := verifyLogChain(logPath, chainStatePath(logPath), "")
	if err != nil {
		return checkResult{name: "log-chain", ok: false,
			message: fmt.Sprintf("cannot verify log chain: %v", err)}
	}
	switch {
	case rep.ChainedLines == 0:
		return checkResult{name: "log-chain", ok: true, optional: true,
			message: "no chained log lines yet"}
	case rep.Tampered():
		var parts []string
		if rep.DivergenceLine != 0 {
			parts = append(parts, fmt.Sprintf("line %d: %s", rep.DivergenceLine, rep.DivergenceReason))
		}
		if rep.SidecarMismatch {
			parts = append(parts, "sidecar head disagrees with log tail")
		}
		return checkResult{name: "log-chain", ok: false,
			message: "log chain BROKEN — " + strings.Join(parts, "; ")}
	default:
		msg := fmt.Sprintf("verified — %d chained lines, head %s", rep.ChainedLines, rep.Head[:16])
		if rep.StartsMidChain {
			msg += " (starts mid-chain after a truncation)"
		}
		return checkResult{name: "log-chain", ok: true, message: msg}
	}
}

// checkFilePerms audits the security-relevant config/state files for
// group/other bits — writers use 0600, so drift means a manual copy or an
// older version created them loose. Warn (optional), not fail: the exposure
// is readability by other local users, not writability.
func checkFilePerms() checkResult {
	targets := []string{}
	if dir := omasealConfigDir(); dir != "" {
		targets = append(targets,
			filepath.Join(dir, "ai-manifest.txt"),
			filepath.Join(dir, "agent.json"),
			filepath.Join(dir, "config.json"),
			filepath.Join(dir, "anchors.log"))
	}
	if base := svcXDGDir("XDG_STATE_HOME", ".local", "state"); base != "" {
		targets = append(targets, filepath.Join(base, "omaseal", "omaseal.log"))
	}
	loose := loosePermFiles(targets)
	if len(loose) > 0 {
		return checkResult{name: "file-perms", ok: true, optional: true,
			message: "loose permissions (want 600): " + strings.Join(loose, ", ") +
				" — chmod 600 them; group/other can read your policy and access history"}
	}
	return checkResult{name: "file-perms", ok: true, message: "policy/config/log files are 0600"}
}

// loosePermFiles returns the basenames of existing files with group/other
// permission bits set. Absent files are skipped — nothing to protect yet.
func loosePermFiles(paths []string) []string {
	var loose []string
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Mode().Perm()&0077 != 0 {
			loose = append(loose, fmt.Sprintf("%s (%o)", filepath.Base(p), fi.Mode().Perm()))
		}
	}
	return loose
}

// dirOnPATH reports whether dir appears verbatim in PATH.
func dirOnPATH(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

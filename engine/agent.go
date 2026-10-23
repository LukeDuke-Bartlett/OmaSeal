package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	agentConfigDirName = "omaseal"
	agentPolicyFile    = "agent.json"
	agentSessionFile   = "session"
)

// AgentPolicy is the user-controlled gate for agent/MCP access.
// mode:
//   - "open"  : agents can read and write secrets freely. Opt-in only — the
//     default for a missing policy is "ask", never "open".
//   - "ask"   : agents need a live session before any MCP tool that touches
//     secrets. A session is minted by `omaseal agent unlock` (biometric if
//     available) OR by any passphrase-verified store unlock — CLI get/set,
//     the panel's unlock field, or a Secret Service Prompt through the
//     provider daemon — because a correct passphrase is the same presence
//     proof. `omaseal agent lock` revokes the session file.
//   - "lock"  : agents cannot access secrets at all. The provider daemon
//     fails closed too — per-call gate, live sessions included.
//
// primary_agent is the user's main agent; agents lists the assigned defaults.
// Both are used by `omaseal mcp install-detected` and `omaseal setup` so the
// agents the user actually runs are wired to OmaSeal automatically.
//
// allow_ungated is the deliberate opt-out from user-presence confirmation in
// ask mode (no biometric + no GUI prompter available). It is set only by
// `omaseal agent mode ask --ungated` and cleared by any other `agent mode`
// invocation, so it is never on silently.
type AgentPolicy struct {
	Mode           string   `json:"mode"`
	SessionMinutes int      `json:"session_minutes"`
	KeepAlive      bool     `json:"keep_alive,omitempty"`
	AllowUngated   bool     `json:"allow_ungated,omitempty"`
	PrimaryAgent   string   `json:"primary_agent,omitempty"`
	Agents         []string `json:"agents,omitempty"`
}

// defaultAgentPolicy is the fail-closed baseline: a missing policy file means
// agents must unlock before touching secrets. "open" exists only when the
// user writes it explicitly. An invalid mode in a present file also resolves
// to this default, so corruption fails closed too.
func defaultAgentPolicy() AgentPolicy {
	return AgentPolicy{Mode: "ask", SessionMinutes: 15}
}

// omasealConfigDir resolves $XDG_CONFIG_HOME/omaseal (or ~/.config/omaseal)
// without creating it — write paths layer MkdirAll on top so reads never
// conjure the directory as a side effect.
func omasealConfigDir() string {
	base := svcXDGDir("XDG_CONFIG_HOME", ".config")
	if base == "" {
		return ""
	}
	return filepath.Join(base, agentConfigDirName)
}

func agentConfigDir() string {
	dir := omasealConfigDir()
	if dir == "" {
		return ""
	}
	_ = os.MkdirAll(dir, 0700)
	return dir
}

func agentPolicyPath() string {
	return filepath.Join(agentConfigDir(), agentPolicyFile)
}

func loadAgentPolicy() (AgentPolicy, error) {
	path := agentPolicyPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultAgentPolicy(), nil
		}
		return defaultAgentPolicy(), err
	}
	var p AgentPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return defaultAgentPolicy(), err
	}
	if !isValidMode(p.Mode) {
		p.Mode = defaultAgentPolicy().Mode
	}
	if p.SessionMinutes <= 0 {
		p.SessionMinutes = defaultAgentPolicy().SessionMinutes
	}
	return p, nil
}

func saveAgentPolicy(p AgentPolicy) error {
	path := agentPolicyPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileMode(path, data, 0600)
}

// loadAgentPolicyOrDefault returns the persisted policy, or defaults when the
// file is missing/unreadable. Use for display paths; CheckAgentOperation must
// keep using loadAgentPolicy so a corrupt policy fails closed there.
func loadAgentPolicyOrDefault() AgentPolicy {
	p, _ := loadAgentPolicy()
	return p
}

func isValidMode(mode string) bool {
	switch mode {
	case "open", "ask", "lock":
		return true
	}
	return false
}

// agentRuntimeDir returns a per-user, non-persistent directory for the session
// token. Prefer XDG_RUNTIME_DIR (tmpfs) so the session is cleared on logout.
func agentRuntimeDir() string {
	if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" {
		dir := filepath.Join(base, agentConfigDirName)
		_ = os.MkdirAll(dir, 0700)
		return dir
	}
	dir := fmt.Sprintf("/tmp/%s-%d", agentConfigDirName, os.Getuid())
	_ = os.MkdirAll(dir, 0700)
	return dir
}

func agentSessionPath() string {
	return filepath.Join(agentRuntimeDir(), agentSessionFile)
}

func writeSessionExpiry(expiry time.Time) error {
	path := agentSessionPath()
	return writeFileMode(path, []byte(sessionExpiryText(expiry)), 0600)
}

// mintAgentSessionIfAsk arms the agent session after a passphrase-verified
// store unlock (any path: TTY/GUI prompt inside list/get, panel field). A
// correct passphrase is the same presence proof UnlockAgent relies on, so
// ask-mode callers get one unlock for the store and the agent window alike.
// Mode "lock" still denies agents; mode "open" needs no session. Never
// shrinks an existing session that already outlives the new window.
func mintAgentSessionIfAsk() {
	p, err := loadAgentPolicy()
	if err != nil || p.Mode != "ask" {
		return
	}
	expiry := time.Now().UTC().Add(time.Duration(p.SessionMinutes) * time.Minute)
	if cur, ok := readSessionExpiry(); ok && cur.After(expiry) {
		return
	}
	if err := writeSessionExpiry(expiry); err != nil {
		WriteLog("agent session mint after store unlock failed: %v", err)
		return
	}
	// The unlock also armed same-UID agents — say so on stderr (stdout can
	// carry a secret) so the grant is never silent.
	fmt.Fprintf(os.Stderr, "omaseal: store unlock armed the agent session for %dm — `omaseal agent lock` revokes\n", p.SessionMinutes)
}

// renewSessionExpiry updates an existing session file in place. Unlike
// writeSessionExpiry it never creates the file, so a keep-alive renewal can
// never resurrect a session revoked by `agent lock` mid-operation. The
// payload is fixed-width and written in one call so a concurrent reader can
// never observe a torn (empty or partial) expiry.
func renewSessionExpiry(expiry time.Time) error {
	f, err := os.OpenFile(agentSessionPath(), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(sessionExpiryText(expiry)))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// sessionExpiryText renders an expiry as a zero-padded fixed-width unix
// timestamp so in-place renewals always overwrite a same-length record.
func sessionExpiryText(expiry time.Time) string {
	return fmt.Sprintf("%020d", expiry.Unix())
}

func readSessionExpiry() (time.Time, bool) {
	data, err := os.ReadFile(agentSessionPath())
	if err != nil {
		return time.Time{}, false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(ts, 0).UTC(), true
}

func clearAgentSession() error {
	var nerr error
	if ns, ok := currentStore.(*nativeStore); ok {
		nerr = ns.clearNativeSession()
	}
	// The unlock-epoch marker is how a running provider daemon revokes a
	// prompt-derived in-memory unlock — agent lock must reach it too.
	return errors.Join(nerr, removeIfExists(agentSessionPath()), removeIfExists(svcUnlockEpochPath()))
}

// AgentMode returns the current mode for use in status/CLI output.
func AgentMode() string {
	p := loadAgentPolicyOrDefault()
	return p.Mode
}

// CheckAgentOperation returns an error if the current agent policy forbids op.
// op is one of: list, get, resolve, set, delete.
func CheckAgentOperation(op string) error {
	p, err := loadAgentPolicy()
	if err != nil {
		return newError("agent_policy_read", "omaseal doctor", fmt.Errorf("cannot load agent policy: %w", err))
	}

	switch p.Mode {
	case "open":
		return nil
	case "lock":
		return newError("agent_locked", "omaseal agent mode open", fmt.Errorf("agent access is locked"))
	case "ask":
		if agentSessionActive(p) {
			return nil
		}
		return newError("agent_unauthorized", "omaseal agent unlock", fmt.Errorf("agent must unlock before %s", op))
	}
	return nil
}

// agentSessionActive reports whether an unlock session is currently valid.
// With keep-alive on, each authorized check slides the window forward.
func agentSessionActive(p AgentPolicy) bool {
	expiry, ok := readSessionExpiry()
	if !ok || !time.Now().UTC().Before(expiry) {
		return false
	}
	if p.KeepAlive {
		_ = renewSessionExpiry(time.Now().UTC().Add(time.Duration(p.SessionMinutes) * time.Minute))
	}
	return true
}

// SetAgentMode changes the persistent agent policy, preserving keep-alive,
// primary, and default-agent assignments. allowUngated opts ask mode out of
// user-presence confirmation — it is only meaningful with "ask" and is reset
// to false by every call that does not explicitly pass it.
func SetAgentMode(mode string, sessionMinutes int, allowUngated bool) error {
	if !isValidMode(mode) {
		return fmt.Errorf("invalid mode %q; use open, ask, or lock", mode)
	}
	p, err := loadAgentPolicy()
	if err != nil {
		return err
	}
	p.Mode = mode
	p.AllowUngated = mode == "ask" && allowUngated
	if sessionMinutes > 0 {
		p.SessionMinutes = sessionMinutes
	}
	return saveAgentPolicy(p)
}

// modeChangeWeakens reports whether switching policy p to (mode, ungated)
// lowers the protection the agent boundary currently has. Those transitions
// are what a prompt-injected agent would run to defeat ask mode, so they go
// through the presence gate; strengthening changes are always free.
func modeChangeWeakens(p AgentPolicy, mode string, ungated bool) bool {
	switch {
	case mode == "open" && p.Mode != "open":
		return true
	case ungated && !p.AllowUngated:
		return true // opting ask out of presence confirmation weakens it
	case p.Mode == "lock" && mode == "ask":
		return true // lock -> ask re-enables agent access
	}
	return false
}

// gateModeChange runs the presence chain for weakening mode transitions.
// No mechanism = refuse: the earlier warn-and-allow made the gate an env
// check, since a caller can suppress every prompter via its own environment
// (OMASEAL_GUI_PROMPT=off, stripped DISPLAY). Genuinely headless machines
// keep a deliberate escape hatch — editing agent.json directly — which
// requires filesystem intent, not just a flag.
func gateModeChange(ctx context.Context, p AgentPolicy, mode string, ungated bool) error {
	if !modeChangeWeakens(p, mode, ungated) {
		return nil
	}
	reason := "change agent mode to " + mode
	if ungated {
		reason += " --ungated"
	}
	switch err := runPresenceChain(ctx, reason); {
	case err == nil:
		return nil
	case errors.Is(err, errNoPresenceMechanism):
		WriteLog("presence: no mechanism to confirm mode change to %s — refused", mode)
		return fmt.Errorf("%w — refusing a weaker agent mode.\n  Headless machines: edit %s directly (deliberate, filesystem-level opt-out)", errNoPresenceMechanism, agentPolicyPath())
	default:
		return err
	}
}

// readPassphraseStdin supplies the --passphrase-stdin value — a stub seam for
// tests. A TTY refuses (typed input would echo); piped input is read with a
// deadline so a held-open pipe can't hang the caller.
var readPassphraseStdin = func() (string, error) {
	if stdinIsTTY() {
		return "", errors.New("--passphrase-stdin requires piped input; run `omaseal agent unlock` for a masked prompt")
	}
	s, err := readSecretFrom(os.Stdin, 30*time.Second)
	return strings.TrimRight(s, "\r\n"), err
}

// UnlockAgent creates a time-bounded session after a user-presence
// confirmation the calling process cannot answer itself (fingerprint, then
// GUI confirm). With no presence mechanism it fails closed unless the policy
// carries the deliberate allow_ungated opt-out.
//
// passphraseStdin is the panel/GUI path: the passphrase is read from stdin
// and unlockIdentity verifies it cryptographically — a correct passphrase IS
// presence proof stronger than a dialog click, so the presence chain is
// skipped. Only meaningful on the native backend, and the agent session is
// written only after the store verifies the passphrase.
func UnlockAgent(passphraseStdin bool) error {
	p, err := loadAgentPolicy()
	if err != nil {
		return err
	}
	if p.Mode == "lock" {
		return fmt.Errorf("agent mode is locked; run `omaseal agent mode ask` (or open) first")
	}
	if p.Mode == "open" {
		fmt.Println("Agent mode is open; unlock is not needed.")
		return nil
	}

	if passphraseStdin {
		ns, ok := currentStore.(*nativeStore)
		if !ok {
			return errors.New("--passphrase-stdin requires backend: native")
		}
		pass, err := readPassphraseStdin()
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		if pass == "" {
			return errors.New("empty passphrase on stdin")
		}
		expiry := time.Now().UTC().Add(time.Duration(p.SessionMinutes) * time.Minute)
		if err := ns.unlockIdentity(pass, expiry); err != nil {
			WriteLog("presence: passphrase unlock failed (stdin)")
			return fmt.Errorf("native store unlock: %w", err)
		}
		if err := writeSessionExpiry(expiry); err != nil {
			if cerr := ns.clearNativeSession(); cerr != nil {
				return fmt.Errorf("%w (native session material remains: %v)", err, cerr)
			}
			return err
		}
		WriteLog("presence: passphrase-verified agent unlock (stdin)")
		fmt.Printf("Agent access unlocked until %s (%d minutes).\n", expiry.Format(time.RFC3339), p.SessionMinutes)
		fmt.Println("Native store unlocked for the same window.")
		return nil
	}

	if err := requireUserPresence(context.Background(), "agent unlock", p); err != nil {
		return fmt.Errorf("agent unlock denied: %w", err)
	}

	expiry := time.Now().UTC().Add(time.Duration(p.SessionMinutes) * time.Minute)
	if err := writeSessionExpiry(expiry); err != nil {
		return err
	}
	fmt.Printf("Agent access unlocked until %s (%d minutes).\n", expiry.Format(time.RFC3339), p.SessionMinutes)

	// Native backend: the agent session alone doesn't give agents a
	// decryption path — seed the tmpfs session identity under the same
	// expiry so Get can unwrap for the window. Prompts on the TTY, or a
	// masked GUI prompt when a graphical session has no TTY (e.g. the
	// panel's Unlock button); only truly headless callers land here.
	if ns, ok := currentStore.(*nativeStore); ok {
		if pass, err := nativePassphrasePrompt("OmaSeal passphrase"); err == nil && pass != "" {
			if err := ns.unlockIdentity(pass, expiry); err != nil {
				return fmt.Errorf("native store unlock: %w", err)
			}
			fmt.Println("Native store unlocked for the same window.")
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "warning: native store still locked — prompt failed: %v; re-run `omaseal agent unlock` to retry.\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "warning: native store still locked — empty passphrase; re-run `omaseal agent unlock` to retry.")
		}
	}
	return nil
}

// LockAgent revokes any active agent session and, if mode is not locked, sets
// the persistent policy to ask so the next access requires re-authorization.
func LockAgent() error {
	if err := clearAgentSession(); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear agent session: %w", err)
	}
	p, err := loadAgentPolicy()
	if err != nil {
		return err
	}
	if p.Mode == "open" {
		if err := SetAgentMode("ask", p.SessionMinutes, false); err != nil {
			return err
		}
	}
	fmt.Println("Agent session cleared. Agent mode is now " + AgentMode() + ".")
	return nil
}

// PrintAgentStatus writes the current policy and session state to stderr.
func PrintAgentStatus() {
	p, err := loadAgentPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot load agent policy: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "agent mode:       %s\n", p.Mode)
	fmt.Fprintf(os.Stderr, "session minutes:  %d\n", p.SessionMinutes)
	keepAlive := "off"
	if p.KeepAlive {
		keepAlive = "on"
	}
	fmt.Fprintf(os.Stderr, "keep-alive:       %s\n", keepAlive)
	if p.PrimaryAgent != "" {
		fmt.Fprintf(os.Stderr, "primary agent:    %s\n", p.PrimaryAgent)
	}
	if len(p.Agents) > 0 {
		fmt.Fprintf(os.Stderr, "default agents:   %s\n", strings.Join(p.Agents, ", "))
	}
	if p.Mode == "ask" {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		fmt.Fprintf(os.Stderr, "presence gate:    %s\n", presenceMechanism(ctx, p, fprintdUsableFunc(ctx)))
		cancel()
		if p.AllowUngated {
			fmt.Fprintln(os.Stderr, "allow_ungated:    on (deliberate — unlock proceeds without confirmation when no mechanism is available)")
		}
	}
	expiry, ok := readSessionExpiry()
	if ok && time.Now().UTC().Before(expiry) {
		fmt.Fprintf(os.Stderr, "session:          active until %s\n", expiry.Format(time.RFC3339))
	} else {
		fmt.Fprintln(os.Stderr, "session:          none")
	}
}

// agentStatusJSON returns the policy and session state as a JSON object for
// panels, plugins, and scripts.
func agentStatusJSON() (string, error) {
	p, err := loadAgentPolicy()
	if err != nil {
		return "", err
	}
	agents := p.Agents
	if agents == nil {
		agents = []string{} // JSON contract: always an array, never null
	}
	backend := "secretservice"
	if _, ok := currentStore.(*nativeStore); ok {
		backend = "native"
	}
	out := map[string]any{
		"mode":            p.Mode,
		"session_minutes": p.SessionMinutes,
		"keep_alive":      p.KeepAlive,
		"session_active":  false,
		"primary_agent":   p.PrimaryAgent,
		"agents":          agents,
		// Panels key their unlock UX off this: native needs an inline
		// passphrase field feeding --passphrase-stdin; secretservice's
		// presence dialog asks for nothing.
		"backend": backend,
	}
	// The presence probe spawns subprocesses; only ask mode consumes the fields.
	if p.Mode == "ask" {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		usable := fprintdUsableFunc(ctx)
		out["fprintd_available"] = usable
		out["allow_ungated"] = p.AllowUngated
		out["presence_gate"] = presenceMechanism(ctx, p, usable)
		cancel()
	}
	if expiry, ok := readSessionExpiry(); ok && time.Now().UTC().Before(expiry) {
		out["session_active"] = true
		out["session_expires"] = expiry.Format(time.RFC3339)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unknownAgentError(name string) error {
	return fmt.Errorf("unknown agent %q; try %s", name, strings.Join(canonicalAgentNames(), ", "))
}

// SetPrimaryAgent records the user's main agent.
func SetPrimaryAgent(name string) error {
	spec, ok := findAgentSpec(name)
	if !ok {
		return unknownAgentError(name)
	}
	p, err := loadAgentPolicy()
	if err != nil {
		return err
	}
	p.PrimaryAgent = spec.name
	return saveAgentPolicy(p)
}

// SetDefaultAgents replaces the assigned default agent list. An empty list
// clears it. Names are validated against the known agent specs.
func SetDefaultAgents(names []string) error {
	clean := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		spec, ok := findAgentSpec(n)
		if !ok {
			return unknownAgentError(n)
		}
		if !seen[spec.name] {
			seen[spec.name] = true
			clean = append(clean, spec.name)
		}
	}
	p, err := loadAgentPolicy()
	if err != nil {
		return err
	}
	p.Agents = clean
	return saveAgentPolicy(p)
}

// SetKeepAlive toggles the sliding session window for ask mode. When on, each
// authorized agent operation renews the session; it expires after
// SessionMinutes of inactivity. When off, the expiry set at unlock is fixed.
func SetKeepAlive(on bool) error {
	p, err := loadAgentPolicy()
	if err != nil {
		return err
	}
	p.KeepAlive = on
	return saveAgentPolicy(p)
}

func handleAgent() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: omaseal agent mode <open|ask|lock> [session-minutes] [--ungated]")
		fmt.Fprintln(os.Stderr, "       omaseal agent unlock")
		fmt.Fprintln(os.Stderr, "       omaseal agent lock")
		fmt.Fprintln(os.Stderr, "       omaseal agent status [--json]")
		fmt.Fprintln(os.Stderr, "       omaseal agent keepalive [on|off]  (no arg = show current)")
		fmt.Fprintf(os.Stderr, "       omaseal agent primary <%s>\n", strings.Join(canonicalAgentNames(), "|"))
		fmt.Fprintln(os.Stderr, "       omaseal agent defaults [names...]  (no names = show current)")
		os.Exit(1)
	}
	sub := os.Args[2]
	switch sub {
	case "mode":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "error: missing mode")
			os.Exit(1)
		}
		mode := os.Args[3]
		mins := 0
		ungated := false
		for _, a := range os.Args[4:] {
			if a == "--ungated" {
				ungated = true
				continue
			}
			m, err := strconv.Atoi(a)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid session minutes: %v\n", err)
				os.Exit(1)
			}
			mins = m
		}
		if ungated && mode != "ask" {
			fmt.Fprintln(os.Stderr, "error: --ungated only applies to `agent mode ask`")
			os.Exit(1)
		}
		if err := gateModeChange(context.Background(), loadAgentPolicyOrDefault(), mode, ungated); err != nil {
			fmt.Fprintf(os.Stderr, "error: mode change denied: %v\n", err)
			os.Exit(1)
		}
		if err := SetAgentMode(mode, mins, ungated); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if ungated {
			WriteLog("agent mode set to %s with allow_ungated", mode)
			fmt.Fprintln(os.Stderr, "warning: agent unlock will skip user-presence confirmation when no mechanism is available — any local process can unlock the agent session.")
		}
		WriteLog("agent mode set to %s (%dm)", mode, mins)
		fmt.Printf("Agent mode set to %s.\n", mode)
	case "unlock":
		if err := UnlockAgent(hasFlag(os.Args, "--passphrase-stdin")); err != nil {
			printError("", err)
			os.Exit(1)
		}
		WriteLog("agent unlocked")
	case "lock":
		if err := LockAgent(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		WriteLog("agent locked")
	case "status":
		if hasFlag(os.Args, "--json") {
			s, err := agentStatusJSON()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(s)
		} else {
			PrintAgentStatus()
		}
	case "keepalive", "keep-alive":
		if len(os.Args) < 4 {
			p := loadAgentPolicyOrDefault()
			if p.KeepAlive {
				fmt.Println("keep-alive: on")
			} else {
				fmt.Println("keep-alive: off")
			}
			return
		}
		var on bool
		switch strings.ToLower(os.Args[3]) {
		case "on", "true", "1", "yes":
			on = true
		case "off", "false", "0", "no":
			on = false
		default:
			fmt.Fprintf(os.Stderr, "error: invalid keepalive value %q; use on or off\n", os.Args[3])
			os.Exit(1)
		}
		if err := SetKeepAlive(on); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		WriteLog("agent keep-alive set to %v", on)
		if on {
			fmt.Println("Agent session keep-alive enabled — sessions renew on activity.")
		} else {
			fmt.Println("Agent session keep-alive disabled — unlock expiry is fixed.")
		}
	case "primary":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "error: missing agent name")
			os.Exit(1)
		}
		if err := SetPrimaryAgent(os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		WriteLog("primary agent set to %s", os.Args[3])
		fmt.Printf("Primary agent set to %s.\n", os.Args[3])
	case "defaults":
		if len(os.Args) < 4 {
			p := loadAgentPolicyOrDefault()
			if len(p.Agents) == 0 {
				fmt.Println("No default agents assigned.")
			} else {
				fmt.Println(strings.Join(p.Agents, ", "))
			}
			return
		}
		names := os.Args[3:]
		if len(names) == 1 && names[0] == "--clear" {
			names = nil
		}
		if err := SetDefaultAgents(names); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		WriteLog("default agents set to %v", names)
		if len(names) == 0 {
			fmt.Println("Default agents cleared.")
		} else {
			fmt.Printf("Default agents set to %s.\n", strings.Join(names, ", "))
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown agent subcommand %q\n", sub)
		os.Exit(1)
	}
}

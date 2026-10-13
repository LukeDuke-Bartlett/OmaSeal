package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubPresence replaces the three chain seams for one test and restores them
// after. usable/verifyErr drive the fprintd step; guiErr drives the GUI step.
func stubPresence(t *testing.T, usable bool, verifyErr, guiErr error) {
	t.Helper()
	oldU, oldV, oldG := fprintdUsableFunc, fprintdVerifyFunc, guiPresenceConfirmFunc
	fprintdUsableFunc = func(context.Context) bool { return usable }
	fprintdVerifyFunc = func(context.Context, string) error { return verifyErr }
	guiPresenceConfirmFunc = func(context.Context, string) error { return guiErr }
	t.Cleanup(func() {
		fprintdUsableFunc, fprintdVerifyFunc, guiPresenceConfirmFunc = oldU, oldV, oldG
	})
}

func TestPresenceFingerprintAllow(t *testing.T) {
	stubPresence(t, true, nil, errors.New("gui must not run"))
	if err := requireUserPresence(context.Background(), "agent unlock", AgentPolicy{}); err != nil {
		t.Fatalf("fingerprint match should allow: %v", err)
	}
}

func TestPresenceFingerprintFailDeniesNoFallback(t *testing.T) {
	guiRan := false
	stubPresence(t, true, errors.New("verify-no-match"), nil)
	oldG := guiPresenceConfirmFunc
	guiPresenceConfirmFunc = func(context.Context, string) error { guiRan = true; return nil }
	defer func() { guiPresenceConfirmFunc = oldG }()

	err := requireUserPresence(context.Background(), "agent unlock", AgentPolicy{AllowUngated: true})
	if !errors.Is(err, errPresenceDenied) {
		t.Fatalf("failed fingerprint must deny, got %v", err)
	}
	if guiRan {
		t.Fatal("a failed fingerprint must not fall through to GUI confirm")
	}
}

func TestPresenceGuiConfirmAllow(t *testing.T) {
	stubPresence(t, false, nil, nil)
	if err := requireUserPresence(context.Background(), "reveal svc/acct", AgentPolicy{}); err != nil {
		t.Fatalf("gui allow should allow: %v", err)
	}
}

func TestPresenceGuiDeclinedDeniesEvenWhenUngated(t *testing.T) {
	// A user who just clicked Deny answered the question — allow_ungated is
	// for machines with no mechanism, not for overriding a refusal.
	stubPresence(t, false, nil, errPromptCancelled)
	err := requireUserPresence(context.Background(), "agent unlock", AgentPolicy{AllowUngated: true})
	if !errors.Is(err, errPresenceDenied) {
		t.Fatalf("declined confirm must deny, got %v", err)
	}
}

func TestPresenceNoMechanismFailsClosed(t *testing.T) {
	stubPresence(t, false, nil, errNoGUIPrompter)
	err := requireUserPresence(context.Background(), "agent unlock", AgentPolicy{})
	if !errors.Is(err, errPresenceDenied) {
		t.Fatalf("no mechanism without opt-out must deny, got %v", err)
	}
	if !strings.Contains(err.Error(), "--ungated") {
		t.Errorf("deny should name the remediation path, got %q", err)
	}
}

func TestPresenceUngatedAllowsWithWarning(t *testing.T) {
	stubPresence(t, false, nil, errors.New("zenity spawn failed"))
	if err := requireUserPresence(context.Background(), "agent unlock", AgentPolicy{AllowUngated: true}); err != nil {
		t.Fatalf("allow_ungated should allow: %v", err)
	}
}

func TestUnlockAgentDeniedWritesNoSession(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, false)
	stubPresence(t, false, nil, errNoGUIPrompter)

	if err := UnlockAgent(false); err == nil {
		t.Fatal("unlock must fail with no presence mechanism")
	}
	p, _ := loadAgentPolicy()
	if agentSessionActive(p) {
		t.Fatal("denied unlock must not leave an active session")
	}
	if _, err := os.Stat(agentSessionPath()); !os.IsNotExist(err) {
		t.Fatalf("denied unlock must not write a session file: %v", err)
	}
	// The MCP gate must stay unauthorized after a failed unlock.
	if err := CheckAgentOperation("get"); err == nil {
		t.Fatal("agent op should stay unauthorized after denied unlock")
	}
}

func TestUnlockAgentUngatedWritesSession(t *testing.T) {
	setupAgentEnv(t)
	if err := saveAgentPolicy(AgentPolicy{Mode: "ask", SessionMinutes: 15, AllowUngated: true}); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	stubPresence(t, false, nil, errNoGUIPrompter)

	if err := UnlockAgent(false); err != nil {
		t.Fatalf("ungated unlock should succeed: %v", err)
	}
	p, _ := loadAgentPolicy()
	if !agentSessionActive(p) {
		t.Fatal("ungated unlock should create an active session")
	}
	if err := CheckAgentOperation("get"); err != nil {
		t.Fatalf("agent op should pass with active session: %v", err)
	}
}

func TestUnlockAgentStillDeniedInLockMode(t *testing.T) {
	setupAgentEnv(t)
	if err := saveAgentPolicy(AgentPolicy{Mode: "lock", SessionMinutes: 15}); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	stubPresence(t, false, nil, nil) // gui would allow; lock must deny anyway
	if err := UnlockAgent(false); err == nil {
		t.Fatal("lock mode must deny unlock before presence is consulted")
	}
}

func TestSetAgentModeUngatedLifecycle(t *testing.T) {
	setupAgentEnv(t)

	if err := SetAgentMode("ask", 15, true); err != nil {
		t.Fatalf("set ask --ungated: %v", err)
	}
	p, _ := loadAgentPolicy()
	if !p.AllowUngated {
		t.Fatal("mode ask --ungated must persist allow_ungated")
	}

	if err := SetAgentMode("ask", 15, false); err != nil {
		t.Fatalf("set ask: %v", err)
	}
	p, _ = loadAgentPolicy()
	if p.AllowUngated {
		t.Fatal("plain `mode ask` must clear allow_ungated")
	}

	// --ungated on a non-ask mode must never stick, even if the CLI check is
	// bypassed.
	if err := SetAgentMode("open", 0, true); err != nil {
		t.Fatalf("set open: %v", err)
	}
	p, _ = loadAgentPolicy()
	if p.AllowUngated {
		t.Fatal("allow_ungated must not persist on non-ask modes")
	}
}

func TestPresenceMechanismLabels(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("OMASEAL_GUI_PROMPT", "off") // pinentry/zenity probes disabled

	ctx := context.Background()
	if got := presenceMechanism(ctx, AgentPolicy{}, true); got != "fprintd" {
		t.Errorf("mechanism = %q, want fprintd", got)
	}
	if got := presenceMechanism(ctx, AgentPolicy{}, false); !strings.HasPrefix(got, "none") {
		t.Errorf("mechanism = %q, want none-*", got)
	}
	if got := presenceMechanism(ctx, AgentPolicy{AllowUngated: true}, false); !strings.HasPrefix(got, "ungated") {
		t.Errorf("mechanism = %q, want ungated*", got)
	}
}

func TestUnlockAgentOpenModeIsNoOp(t *testing.T) {
	setupAgentEnv(t)
	if err := saveAgentPolicy(AgentPolicy{Mode: "open", SessionMinutes: 15}); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	stubPresence(t, false, nil, errNoGUIPrompter) // gate must not even run
	if err := UnlockAgent(false); err != nil {
		t.Fatalf("open-mode unlock should be a no-op, got %v", err)
	}
}

// --- mode-change gate ---

func TestModeChangeWeakens(t *testing.T) {
	ask := AgentPolicy{Mode: "ask"}
	askUngated := AgentPolicy{Mode: "ask", AllowUngated: true}
	open := AgentPolicy{Mode: "open"}
	lock := AgentPolicy{Mode: "lock"}

	cases := []struct {
		name       string
		p          AgentPolicy
		mode       string
		ungated    bool
		wantWeaken bool
	}{
		{"ask->open", ask, "open", false, true},
		{"ask->ask+ungated", ask, "ask", true, true},
		{"lock->open", lock, "open", false, true},
		{"lock->ask", lock, "ask", false, true},
		{"open->open", open, "open", false, false},
		{"ask+ungated->ask+ungated", askUngated, "ask", true, false},
		{"open->ask", open, "ask", false, false},
		{"ask->lock", ask, "lock", false, false},
		{"ask+ungated->ask", askUngated, "ask", false, false},
	}
	for _, c := range cases {
		if got := modeChangeWeakens(c.p, c.mode, c.ungated); got != c.wantWeaken {
			t.Errorf("%s: modeChangeWeakens = %v, want %v", c.name, got, c.wantWeaken)
		}
	}
}

func TestGateModeChangeStrengtheningNeverAsks(t *testing.T) {
	// A strengthening change must not touch the chain even when a fingerprint
	// reader exists and would fail.
	stubPresence(t, true, errors.New("must not run"), errors.New("must not run"))
	p := AgentPolicy{Mode: "ask"}
	if err := gateModeChange(context.Background(), p, "lock", false); err != nil {
		t.Fatalf("strengthening change should pass unguarded: %v", err)
	}
}

func TestGateModeChangeWeakDeniedByUser(t *testing.T) {
	stubPresence(t, false, nil, errPromptCancelled)
	p := AgentPolicy{Mode: "ask"}
	if err := gateModeChange(context.Background(), p, "open", false); !errors.Is(err, errPresenceDenied) {
		t.Fatalf("user-declined mode change must deny, got %v", err)
	}
}

func TestGateModeChangeWeakAllowedByGui(t *testing.T) {
	stubPresence(t, false, nil, nil)
	p := AgentPolicy{Mode: "ask"}
	if err := gateModeChange(context.Background(), p, "open", false); err != nil {
		t.Fatalf("gui-allowed mode change should pass: %v", err)
	}
}

func TestGateModeChangeNoMechanismRefuses(t *testing.T) {
	// No mechanism = fail closed. Callers can suppress every prompter through
	// their own environment, so warn-and-allow made the gate an env check;
	// the headless escape hatch is editing agent.json directly.
	stubPresence(t, false, nil, errNoGUIPrompter)
	p := AgentPolicy{Mode: "ask"}
	err := gateModeChange(context.Background(), p, "ask", true)
	if !errors.Is(err, errNoPresenceMechanism) {
		t.Fatalf("no-mechanism weakening change must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "agent.json") {
		t.Fatalf("refusal should point at the manual escape hatch, got %v", err)
	}
}

// --- GUI confirm prompters ---

// pinentryConfirmStub is pinentryStub specialized for CONFIRM: it replies
// `confirmReply` to the CONFIRM command and logs every line received.
func pinentryConfirmStub(t *testing.T, flavor, confirmReply string) (path, logPath string) {
	t.Helper()
	logPath = filepath.Join(t.TempDir(), "stub.log")
	script := `#!/usr/bin/env bash
printf 'OK pinentry-stub 1.0\n'
while IFS= read -r line; do
  printf '%s\n' "$line" >> "` + logPath + `"
  case "$line" in
    GETINFO*) printf 'D ` + flavor + `\nOK\n' ;;
    CONFIRM*) ` + confirmReply + ` ;;
    BYE*) printf 'OK\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
exit 0
`
	return writeStub(t, "pinentry", script), logPath
}

func TestConfirmPinentryAllow(t *testing.T) {
	stub, logPath := pinentryConfirmStub(t, "gnome3", `printf 'OK\n'`)
	if err := confirmPinentry(context.Background(), stub, "OmaSeal", "Allow agent unlock?"); err != nil {
		t.Fatalf("confirmPinentry: %v", err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	for _, want := range []string{"CONFIRM", "SETOK Allow", "SETCANCEL Deny", "SETDESC Allow agent unlock"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("stub log missing %q:\n%s", want, log)
		}
	}
}

func TestConfirmPinentryDeny(t *testing.T) {
	stub, _ := pinentryConfirmStub(t, "gnome3", `printf 'ERR 83886179 canceled\n'`)
	if err := confirmPinentry(context.Background(), stub, "t", "d"); !errors.Is(err, errPromptCancelled) {
		t.Fatalf("deny should map to errPromptCancelled, got %v", err)
	}
}

func TestConfirmPinentryCursesSkipped(t *testing.T) {
	stub, _ := pinentryConfirmStub(t, "curses", `printf 'OK\n'`)
	if err := confirmPinentry(context.Background(), stub, "t", "d"); !errors.Is(err, errNoGUIPrompter) {
		t.Fatalf("curses backend is not a GUI prompter, got %v", err)
	}
}

func TestConfirmZenityAllow(t *testing.T) {
	stub := writeStub(t, "zenity", "#!/usr/bin/env bash\nexit 0\n")
	if err := confirmZenity(context.Background(), stub, "t", "d"); err != nil {
		t.Fatalf("exit 0 should allow: %v", err)
	}
}

func TestConfirmZenityDeny(t *testing.T) {
	stub := writeStub(t, "zenity", "#!/usr/bin/env bash\nexit 1\n")
	if err := confirmZenity(context.Background(), stub, "t", "d"); !errors.Is(err, errPromptCancelled) {
		t.Fatalf("exit 1 should map to denied, got %v", err)
	}
}

func TestGuiPresenceConfirmUsesPrompter(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-1")
	t.Setenv("OMASEAL_GUI_PROMPT", "zenity")
	marker := filepath.Join(t.TempDir(), "zenity-ran")
	stub := writeStub(t, "zenity", "#!/usr/bin/env bash\ntouch \""+marker+"\"\nexit 0\n")
	old := zenityCandidatePaths
	zenityCandidatePaths = func() []string { return []string{stub} }
	defer func() { zenityCandidatePaths = old }()

	if err := guiPresenceConfirm(context.Background(), "agent unlock"); err != nil {
		t.Fatalf("guiPresenceConfirm: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("zenity stub never ran")
	}
}

func TestGuiPresenceConfirmNoDisplay(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	if err := guiPresenceConfirm(context.Background(), "agent unlock"); !errors.Is(err, errNoGUIPrompter) {
		t.Fatalf("headless must report no prompter, got %v", err)
	}
}

// --passphrase-stdin: the passphrase is the presence proof — the agent
// session is written only after unlockIdentity verifies it. The presence
// chain must not run at all on this path.
func TestUnlockAgentPassphraseStdin(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, false)

	ns, dir := nativeTestStore(t)
	initNative(t, ns, "panel-pass")
	oldStore := currentStore
	currentStore = newNativeStoreAt(dir, t.TempDir())
	t.Cleanup(func() { currentStore = oldStore })

	// If the presence chain runs at all it errors, failing the test — the
	// passphrase verification is the proof, no dialog may fire.
	stubPresence(t, true, errors.New("presence chain must not run"), errors.New("presence chain must not run"))

	oldStdin := readPassphraseStdin
	readPassphraseStdin = func() (string, error) { return "panel-pass", nil }
	t.Cleanup(func() { readPassphraseStdin = oldStdin })

	if err := UnlockAgent(true); err != nil {
		t.Fatalf("passphrase-stdin unlock: %v", err)
	}
	p, _ := loadAgentPolicy()
	if !agentSessionActive(p) {
		t.Fatal("expected an active agent session")
	}
	// And the store is actually unlocked — not just the session file.
	if _, err := currentStore.Get("svc", "acct"); err != nil {
		t.Fatalf("native store should be readable post-unlock: %v", err)
	}
}

// A wrong passphrase must fail before any session material is written.
func TestUnlockAgentPassphraseStdinWrongPass(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, false)

	ns, dir := nativeTestStore(t)
	initNative(t, ns, "right-pass")
	oldStore := currentStore
	currentStore = newNativeStoreAt(dir, t.TempDir())
	t.Cleanup(func() { currentStore = oldStore })

	oldStdin := readPassphraseStdin
	readPassphraseStdin = func() (string, error) { return "wrong-pass", nil }
	t.Cleanup(func() { readPassphraseStdin = oldStdin })

	err := UnlockAgent(true)
	if err == nil || !strings.Contains(err.Error(), "native store unlock") {
		t.Fatalf("err = %v, want a native-store unlock failure", err)
	}
	p, _ := loadAgentPolicy()
	if agentSessionActive(p) {
		t.Fatal("failed passphrase unlock must not write an agent session")
	}
	if _, err := os.Stat(agentSessionPath()); !os.IsNotExist(err) {
		t.Fatalf("agent session file must not exist: %v", err)
	}
	if _, gerr := currentStore.Get("svc", "acct"); codeFromError(gerr) != "locked" {
		t.Fatalf("store must stay locked after a wrong passphrase: %v", gerr)
	}
}

// Read failures and an empty passphrase fail before verification — no
// session material may be written on either path.
func TestUnlockAgentPassphraseStdinInputErrors(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, false)

	ns, dir := nativeTestStore(t)
	initNative(t, ns, "panel-pass")
	oldStore := currentStore
	currentStore = newNativeStoreAt(dir, t.TempDir())
	t.Cleanup(func() { currentStore = oldStore })

	oldStdin := readPassphraseStdin
	t.Cleanup(func() { readPassphraseStdin = oldStdin })

	for _, tc := range []struct {
		name    string
		stub    func() (string, error)
		wantErr string
	}{
		{"read failure", func() (string, error) { return "", errors.New("boom") }, "read passphrase"},
		{"empty passphrase", func() (string, error) { return "", nil }, "empty passphrase"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readPassphraseStdin = func() (string, error) { return tc.stub() }
			err := UnlockAgent(true)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			p, _ := loadAgentPolicy()
			if agentSessionActive(p) {
				t.Fatal("no session may be written on a bad read")
			}
		})
	}
}

// The real reader refuses a TTY (input would echo) and accepts piped input
// with or without a trailing newline or CRLF ending.
func TestReadPassphraseStdin(t *testing.T) {
	oldTTY := stdinIsTTY
	t.Cleanup(func() { stdinIsTTY = oldTTY })

	stdinIsTTY = func() bool { return true }
	if _, err := readPassphraseStdin(); err == nil || !strings.Contains(err.Error(), "piped input") {
		t.Fatalf("TTY stdin must be refused, got %v", err)
	}

	stdinIsTTY = func() bool { return false }
	oldStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = oldStdin })
	for _, tc := range []struct{ in, want string }{
		{"panel-pass\n", "panel-pass"},
		{"panel-pass", "panel-pass"},
		{"panel-pass\r\n", "panel-pass"},
	} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = r
		go func() { w.WriteString(tc.in); w.Close() }()
		got, err := readPassphraseStdin()
		r.Close()
		if err != nil || got != tc.want {
			t.Fatalf("read(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

// The flag is meaningless on backends without a passphrase — fail loud
// rather than silently ignoring stdin.
func TestUnlockAgentPassphraseStdinNotNative(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, false)

	oldStore := currentStore
	currentStore = ssStore{}
	t.Cleanup(func() { currentStore = oldStore })

	oldStdin := readPassphraseStdin
	readPassphraseStdin = func() (string, error) { return "anything", nil }
	t.Cleanup(func() { readPassphraseStdin = oldStdin })

	err := UnlockAgent(true)
	if err == nil || !strings.Contains(err.Error(), "backend: native") {
		t.Fatalf("err = %v, want a native-backend requirement", err)
	}
}

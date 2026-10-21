package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// graphical forces the session probe on — CI has no display, and the
// prompter binaries are stubbed so nothing real is spawned. The runtime
// dir is isolated so the ask-save throttle stamp can't leak between tests.
func graphical(t *testing.T) {
	t.Helper()
	t.Setenv("WAYLAND_DISPLAY", "test-wayland")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
}

// forceZenity stubs the prompter list to exactly the given zenity script —
// the "user" of askSave in tests.
func forceZenity(t *testing.T, stubBody string) {
	t.Helper()
	zen := zenityStub(t, stubBody)
	oldP, oldZ := pinentryCandidatePaths, zenityCandidatePaths
	pinentryCandidatePaths = func() []string { return nil }
	zenityCandidatePaths = func() []string { return []string{zen} }
	t.Cleanup(func() { pinentryCandidatePaths, zenityCandidatePaths = oldP, oldZ })
	t.Setenv("OMASEAL_GUI_PROMPT", "zenity")
}

func TestAskSaveStoresDialogValue(t *testing.T) {
	ms := mockKeyring(t)
	graphical(t)
	forceZenity(t, `printf 'hunter2\n'`)

	if err := askSave(context.Background(), "svc", "acct", ""); err != nil {
		t.Fatalf("askSave: %v", err)
	}
	got, err := ms.get("svc", "acct")
	if err != nil {
		t.Fatalf("stored value unreadable: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("stored %q, want the dialog value hunter2", got)
	}
}

func TestAskSaveCancelIsTyped(t *testing.T) {
	mockKeyring(t)
	graphical(t)
	forceZenity(t, `exit 1`)

	err := askSave(context.Background(), "svc", "acct", "")
	if code := codeFromError(err); code != "prompt_cancelled" {
		t.Fatalf("code = %q, want prompt_cancelled (err %v)", code, err)
	}
	if !errors.Is(err, errPromptCancelled) {
		t.Errorf("err = %v, want wrapped errPromptCancelled", err)
	}
}

func TestAskSaveNoDisplayIsTyped(t *testing.T) {
	mockKeyring(t)
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	err := askSave(context.Background(), "svc", "acct", "")
	if code := codeFromError(err); code != "no_gui_session" {
		t.Fatalf("code = %q, want no_gui_session (err %v)", code, err)
	}
}

func TestAskSaveGUIDisabledIsTyped(t *testing.T) {
	mockKeyring(t)
	graphical(t)
	t.Setenv("OMASEAL_GUI_PROMPT", "off")

	err := askSave(context.Background(), "svc", "acct", "")
	if code := codeFromError(err); code != "no_gui_prompter" {
		t.Fatalf("code = %q, want no_gui_prompter (err %v)", code, err)
	}
}

func TestAskSaveDescCapped(t *testing.T) {
	ms := mockKeyring(t)
	graphical(t)
	// The stub records argv so the test can prove the description was
	// truncated — agent-supplied dialog copy is untrusted input.
	marker := t.TempDir() + "/desc"
	forceZenity(t, `printf '%s' "$*" > "`+marker+`"; printf 'v\n'`)

	// 'Q' appears nowhere in the dialog boilerplate — counting it isolates
	// the desc from requester-name / arg noise.
	long := strings.Repeat("Q", 500)
	if err := askSave(context.Background(), "svc", "acct", long); err != nil {
		t.Fatalf("askSave: %v", err)
	}
	if _, err := ms.get("svc", "acct"); err != nil {
		t.Fatalf("value not stored: %v", err)
	}
	raw, rerr := os.ReadFile(marker)
	if rerr != nil {
		t.Fatalf("stub did not record argv: %v", rerr)
	}
	if n := strings.Count(string(raw), "Q"); n != 200 {
		t.Errorf("desc should carry exactly the 200-char cap, got %d Q's", n)
	}
}

func TestAskSaveDescSanitized(t *testing.T) {
	mockKeyring(t)
	graphical(t)
	marker := t.TempDir() + "/desc"
	forceZenity(t, `printf '%s' "$*" > "`+marker+`"; printf 'v\n'`)

	// Newlines and control bytes could fake extra prompt lines; they must
	// flatten to spaces, and the note must be labelled untrusted.
	err := askSave(context.Background(), "svc", "acct", "line one\nline two: press OK\x07")
	if err != nil {
		t.Fatalf("askSave: %v", err)
	}
	raw, rerr := os.ReadFile(marker)
	if rerr != nil {
		t.Fatalf("stub did not record argv: %v", rerr)
	}
	got := string(raw)
	if !strings.Contains(got, "Agent note (untrusted): line one line two: press OK") {
		t.Errorf("desc not flattened/labelled: %q", got)
	}
}

func TestAskSaveRateLimited(t *testing.T) {
	mockKeyring(t)
	graphical(t)
	forceZenity(t, `printf 'v\n'`)

	if err := askSave(context.Background(), "svc", "acct", ""); err != nil {
		t.Fatalf("first askSave: %v", err)
	}
	// A cancelled or completed prompt still burns the slot — the second
	// call inside the cooldown is refused before any dialog opens.
	err := askSave(context.Background(), "svc", "acct", "")
	if code := codeFromError(err); code != "rate_limited" {
		t.Fatalf("code = %q, want rate_limited (err %v)", code, err)
	}
}

// MCP surface end-to-end: valid call through callMCPTool prompts (stubbed),
// stores, and returns ok — exercising dispatch, policy, and persistence.
func TestMCPAskSaveStoresDialogValue(t *testing.T) {
	cfg, ms := mcpFixture(t)
	writeAgentPolicy(t, cfg, "open", false)
	graphical(t)
	forceZenity(t, `printf 'hunter2\n'`)

	resp := mcpCall("omaseal_ask_save", map[string]any{"service": "svc", "account": "acct"})
	isErr, txt := mcpIsError(t, resp)
	if isErr || txt != "ok" {
		t.Fatalf("want ok, got isErr=%v text=%q", isErr, txt)
	}
	got, err := ms.get("svc", "acct")
	if err != nil || got != "hunter2" {
		t.Fatalf("stored %q, err %v — want hunter2", got, err)
	}
}

// MCP surface: ask-save is a set-class operation — same gates, and the
// manifest DENY still wins even though the human supplies the value.
func TestMCPAskSaveManifestDeny(t *testing.T) {
	cfg, _ := mcpFixture(t)
	writeAgentPolicy(t, cfg, "open", false)
	writeManifest(t, cfg, "DENY bank/*\n")
	isErr, txt := mcpIsError(t, mcpCall("omaseal_ask_save", map[string]any{"service": "bank", "account": "root"}))
	if !isErr || !strings.Contains(txt, "manifest_denied") {
		t.Fatalf("DENY should refuse with manifest_denied: %q", txt)
	}
}

func TestMCPAskSaveAskModeNeedsSession(t *testing.T) {
	cfg, _ := mcpFixture(t)
	writeAgentPolicy(t, cfg, "ask", false)
	isErr, txt := mcpIsError(t, mcpCall("omaseal_ask_save", map[string]any{"service": "svc", "account": "a"}))
	if !isErr || !strings.Contains(txt, "agent_unauthorized") {
		t.Fatalf("ask mode without session should refuse: %q", txt)
	}
}

func TestMCPAskSaveInvalidName(t *testing.T) {
	cfg, _ := mcpFixture(t)
	writeAgentPolicy(t, cfg, "open", false)
	isErr, txt := mcpIsError(t, mcpCall("omaseal_ask_save", map[string]any{"service": "bad svc", "account": "a"}))
	if !isErr || !strings.Contains(txt, "invalid_name") {
		t.Fatalf("strict name check should refuse: %q", txt)
	}
}

package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const hermesBin = "/usr/bin/omaseal"

func TestHermesYAMLEmptyAndMissingKey(t *testing.T) {
	want := "mcp_servers:\n  omaseal:\n    command: \"/usr/bin/omaseal\"\n    args: [\"mcp\"]\n"
	got, err := hermesYAMLWith("", hermesBin)
	if err != nil || got != want {
		t.Fatalf("empty file:\n got %q (%v)\nwant %q", got, err, want)
	}

	existing := "model: glm\n# my notes\nslack:\n  enabled: true\n"
	got, err = hermesYAMLWith(existing, hermesBin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, existing) || !strings.HasSuffix(got, want) {
		t.Fatalf("unrelated settings and comments must survive verbatim:\n%s", got)
	}
}

func TestHermesYAMLAddsBesideExistingServers(t *testing.T) {
	existing := "model: glm\n" +
		"mcp_servers:\n" +
		"  # linear first\n" +
		"  linear:\n" +
		"    command: \"npx\"\n" +
		"    args: [\"-y\", \"mcp-linear\"]\n" +
		"    env:\n" +
		"      KEY: \"x\"\n" +
		"\n" +
		"# next section\n" +
		"slack:\n" +
		"  enabled: true\n"
	got, err := hermesYAMLWith(existing, hermesBin)
	if err != nil {
		t.Fatal(err)
	}
	want := "model: glm\n" +
		"mcp_servers:\n" +
		"  # linear first\n" +
		"  linear:\n" +
		"    command: \"npx\"\n" +
		"    args: [\"-y\", \"mcp-linear\"]\n" +
		"    env:\n" +
		"      KEY: \"x\"\n" +
		"  omaseal:\n" +
		"    command: \"/usr/bin/omaseal\"\n" +
		"    args: [\"mcp\"]\n" +
		"\n" +
		"# next section\n" +
		"slack:\n" +
		"  enabled: true\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestHermesYAMLReplacesStaleEntryAndIsIdempotent(t *testing.T) {
	existing := "mcp_servers:\n" +
		"    omaseal:\n" +
		"        command: \"/old/omaseal\"\n" +
		"        args: [\"mcp\"]\n" +
		"        env:\n" +
		"            A: b\n" +
		"    other:\n" +
		"        command: \"x\"\n" +
		"after: 1\n"
	once, err := hermesYAMLWith(existing, hermesBin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(once, "/old/omaseal") || strings.Contains(once, "A: b") {
		t.Fatalf("stale entry survived:\n%s", once)
	}
	if !strings.Contains(once, "    other:\n        command: \"x\"\n") || !strings.HasSuffix(once, "after: 1\n") {
		t.Fatalf("sibling or following section damaged:\n%s", once)
	}
	// Indent style of the file (4 spaces) is followed.
	if !strings.Contains(once, "    omaseal:\n        command: \"/usr/bin/omaseal\"\n        args: [\"mcp\"]\n") {
		t.Fatalf("new entry did not follow the file's 4-space indent:\n%s", once)
	}
	twice, err := hermesYAMLWith(once, hermesBin)
	if err != nil || twice != once {
		t.Fatalf("not idempotent:\nonce:\n%s\ntwice:\n%s (%v)", once, twice, err)
	}
	if n := strings.Count(twice, "omaseal:"); n != 1 {
		t.Fatalf("%d omaseal entries", n)
	}
}

func TestHermesYAMLEmptyFlowValueAndInlineRefusal(t *testing.T) {
	got, err := hermesYAMLWith("mcp_servers: {}\nx: 1\n", hermesBin)
	if err != nil || !strings.HasPrefix(got, "mcp_servers:\n  omaseal:\n") || !strings.HasSuffix(got, "x: 1\n") {
		t.Fatalf("empty flow mapping not expanded: %q (%v)", got, err)
	}
	for _, v := range []string{"mcp_servers: {a: {command: x}}\n", "mcp_servers: [a]\n"} {
		if out, err := hermesYAMLWith(v, hermesBin); err == nil {
			t.Fatalf("inline value %q must be refused, got %q", v, out)
		}
	}
}

func TestHermesHasOmaseal(t *testing.T) {
	yes := "mcp_servers:\n  a:\n    command: x\n  omaseal:\n    command: y\n"
	no := "mcp_servers:\n  a:\n    command: x\nother:\n  omaseal:\n    command: y\n"
	if !hermesHasOmaseal(yes) {
		t.Error("missed omaseal under mcp_servers")
	}
	if hermesHasOmaseal(no) {
		t.Error("matched an omaseal key outside mcp_servers")
	}
}

func TestInstallMCPHermesWritesConfigYAMLNotMCPJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("# keep me\nmodel: glm\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	path, err := installMCP("hermes", "")
	if err != nil {
		t.Fatal(err)
	}
	if path != cfg {
		t.Fatalf("installed at %s, want %s", path, cfg)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.HasPrefix(string(b), "# keep me\nmodel: glm\n") || !strings.Contains(string(b), "mcp_servers:\n  omaseal:\n") {
		t.Fatalf("config.yaml:\n%s", b)
	}
	if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o640 {
		t.Errorf("file mode changed to %v", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(home, ".hermes", "mcp.json")); err == nil {
		t.Error("wrote the mcp.json Hermes never reads")
	}

	for _, r := range mcpStatusRows() {
		if r.Name == "hermes" && !r.Installed {
			t.Error("mcp status does not see the installed hermes entry")
		}
	}
}

func TestInstallMCPHermesHasNoProjectConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, err := installMCP("hermes", t.TempDir()); err == nil || !strings.Contains(err.Error(), "no project-level") {
		t.Fatalf("--dir for hermes must be refused, got %v", err)
	}
}

// ── agent mode must not hang forever on the presence confirm ──────────────

func TestAgentModeConfirmTimesOutWithClearMessage(t *testing.T) {
	old := modeChangeConfirmTimeout
	modeChangeConfirmTimeout = 150 * time.Millisecond
	t.Cleanup(func() { modeChangeConfirmTimeout = old })

	stubPresence(t, false, nil, nil)
	// A dialog nobody answers: blocks until its context ends.
	guiPresenceConfirmFunc = func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}

	start := time.Now()
	err := gateModeChange(context.Background(), AgentPolicy{Mode: "ask"}, "open", false)
	if err == nil {
		t.Fatal("loosening the mode with nobody to confirm must be refused")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v; the wait is not bounded", time.Since(start))
	}
	if !errors.Is(err, errPresenceDenied) {
		t.Errorf("want errPresenceDenied, got %v", err)
	}
	for _, want := range []string{"nobody confirmed", "desktop", "agent.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
}

func TestAgentModeConfirmAllowStillWorks(t *testing.T) {
	stubPresence(t, false, nil, nil) // gui returns nil = allowed
	if err := gateModeChange(context.Background(), AgentPolicy{Mode: "ask"}, "open", false); err != nil {
		t.Fatalf("confirmed change must pass: %v", err)
	}
	// Tightening never prompts.
	stubPresence(t, false, nil, errors.New("must not be asked"))
	if err := gateModeChange(context.Background(), AgentPolicy{Mode: "open"}, "lock", false); err != nil {
		t.Fatalf("tightening must not need presence: %v", err)
	}
}

// ── confirmations default to No ───────────────────────────────────────────

func TestSetupConfirmDefaultsToNo(t *testing.T) {
	old := setupReader
	t.Cleanup(func() { setupReader = old })
	for in, want := range map[string]bool{"\n": false, "": false, "n\n": false, "y\n": true, "yes\n": true} {
		setupReader = bufio.NewReader(strings.NewReader(in))
		if got := confirm("Proceed?"); got != want {
			t.Errorf("confirm with input %q = %v, want %v", in, got, want)
		}
		setupReader = bufio.NewReader(strings.NewReader(in))
		if got := confirmExplicit("Enable?"); got != want {
			t.Errorf("confirmExplicit with input %q = %v, want %v", in, got, want)
		}
	}
}

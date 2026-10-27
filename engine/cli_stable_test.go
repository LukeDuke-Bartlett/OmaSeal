package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// These tests pin the output other programs depend on: the Quickshell panel
// (list --json, agent status --json, logs --json, get, set, del), MCP clients
// (the stdio server), plugins (ipc) and scripts. They run the real binary
// with piped stdio — exactly how those consumers call it.

var (
	binOnce sync.Once
	binDir  string
	binPath string
	binErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func testBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "omaseal-bin-")
		if binErr != nil {
			return
		}
		binPath = filepath.Join(binDir, "omaseal")
		out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
		if err != nil {
			binErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatalf("building the binary: %v", binErr)
	}
	return binPath
}

type result struct {
	stdout, stderr string
	code           int
}

// runBinary runs omaseal in a throwaway HOME with piped stdio and no display
// or session bus, so output depends only on the code under test.
func runBinary(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	home := t.TempDir()
	rt := filepath.Join(home, "rt")
	if err := os.Mkdir(rt, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(testBinary(t), args...)
	cmd.Dir = home
	cmd.Env = []string{
		"HOME=" + home, "XDG_CONFIG_HOME=" + home + "/c", "XDG_DATA_HOME=" + home + "/d",
		"XDG_STATE_HOME=" + home + "/s", "XDG_RUNTIME_DIR=" + rt,
		"PATH=" + os.Getenv("PATH"), "TERM=xterm-256color",
	}
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("omaseal %v timed out", args)
	}
	code := cmd.ProcessState.ExitCode()
	return result{so.String(), se.String(), code}
}

func TestVersionOutputsAreStable(t *testing.T) {
	want := fmt.Sprintf("omaseal dev (unknown) %s/%s\n", runtime.GOOS, runtime.GOARCH)
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		r := runBinary(t, "", args...)
		if r.stdout != want || r.code != 0 {
			t.Errorf("omaseal %v: stdout=%q code=%d, want %q code 0", args, r.stdout, r.code, want)
		}
	}
}

func TestIPCPingIsByteStable(t *testing.T) {
	r := runBinary(t, "", "ipc", "ping", "{}")
	if r.stdout != "{\"ok\":\"pong\"}\n" || r.code != 0 {
		t.Fatalf("ipc ping: stdout=%q code=%d", r.stdout, r.code)
	}
}

func keysOf(m map[string]any) []string {
	k := make([]string, 0, len(m))
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

// The panel parses this JSON; its key set must not drift.
func TestAgentStatusJSONKeySetIsStable(t *testing.T) {
	r := runBinary(t, "", "agent", "status", "--json")
	var m map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &m); err != nil {
		t.Fatalf("agent status --json is not JSON: %v\n%q", err, r.stdout)
	}
	want := []string{"agents", "allow_ungated", "backend", "fprintd_available", "keep_alive",
		"mode", "presence_gate", "primary_agent", "session_active", "session_minutes"}
	if got := keysOf(m); !reflect.DeepEqual(got, want) {
		t.Fatalf("agent status --json keys changed:\n got %v\nwant %v", got, want)
	}
	if strings.Count(r.stdout, "\n") != 1 {
		t.Errorf("agent status --json must be a single line, got %q", r.stdout)
	}
}

func TestLogsJSONShapeIsStable(t *testing.T) {
	r := runBinary(t, "", "logs", "25", "--json")
	var rows []map[string]string
	if err := json.Unmarshal([]byte(r.stdout), &rows); err != nil {
		t.Fatalf("logs 25 --json is not a JSON array of objects: %v\n%q", err, r.stdout)
	}
	for _, row := range rows {
		if got := keysOfStr(row); !reflect.DeepEqual(got, []string{"message", "source", "time"}) {
			t.Fatalf("log row keys changed: %v", got)
		}
	}
}

func keysOfStr(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

func TestMCPStatusJSONKeySetIsStable(t *testing.T) {
	r := runBinary(t, "", "mcp", "status", "--json")
	var rows []map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &rows); err != nil {
		t.Fatalf("mcp status --json: %v\n%q", err, r.stdout)
	}
	if len(rows) == 0 {
		t.Fatal("no agents listed")
	}
	for _, row := range rows {
		for _, k := range []string{"name", "detected", "installed", "config"} {
			if _, ok := row[k]; !ok {
				t.Errorf("row %v missing %q", row["name"], k)
			}
		}
	}
	// Hermes must point at the file Hermes actually reads.
	for _, row := range rows {
		if row["name"] == "hermes" && !strings.HasSuffix(row["config"].(string), filepath.Join(".hermes", "config.yaml")) {
			t.Errorf("hermes config = %v, want .hermes/config.yaml", row["config"])
		}
	}
}

// `omaseal mcp` is a JSON-RPC stdio server: stdout must carry protocol and
// nothing else — no banner, no help, no styling.
func TestMCPServerStdoutIsProtocolOnly(t *testing.T) {
	req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n"
	for _, args := range [][]string{{"mcp"}, {"mcp", "serve"}} {
		r := runBinary(t, req, args...)
		lines := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("omaseal %v: want exactly one response line, got %d:\n%q", args, len(lines), r.stdout)
		}
		var resp struct {
			ID     int `json:"id"`
			Result struct {
				Capabilities map[string]any `json:"capabilities"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil || resp.ID != 1 || resp.Result.Capabilities == nil {
			t.Fatalf("omaseal %v: not an initialize response: %v\n%q", args, err, lines[0])
		}
	}
}

// Piped output is never decorated: no ANSI, no glyphs, no banner.
func TestPipedOutputIsNeverDecorated(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--help"}, {"agent", "--help"}, {"doctor"}, {"ping"}, {"agent", "status"},
		{"mcp", "status"}, {"stats"}, {"manifest", "show"}, {"bogus-command"},
	} {
		r := runBinary(t, "", args...)
		all := r.stdout + r.stderr
		for _, bad := range []string{"\x1b[", "✓", "✗", "╭", "▟"} {
			if strings.Contains(all, bad) {
				t.Errorf("omaseal %v decorated piped output with %q:\n%s", args, bad, all)
			}
		}
	}
}

func TestAgentModeConfirmationStdoutIsStable(t *testing.T) {
	// Tightening needs no presence check, so this runs headless.
	r := runBinary(t, "", "agent", "mode", "lock")
	if r.stdout != "Agent mode set to lock.\n" || r.code != 0 {
		t.Fatalf("agent mode lock: stdout=%q code=%d stderr=%q", r.stdout, r.code, r.stderr)
	}
}

func TestRunWithoutDashDashKeepsHandlerError(t *testing.T) {
	r := runBinary(t, "", "run", "-e", "X=a/b")
	if r.code == 0 {
		t.Fatalf("run without a command must fail, got exit 0")
	}
}

// ── in-process, with a fake backend ────────────────────────────────────────

type cliFakeStore struct {
	items map[string]string
	list  []Item
}

func (f *cliFakeStore) Get(s, a string) (string, error) {
	v, ok := f.items[s+"/"+a]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}
func (f *cliFakeStore) Set(s, a, v string) error    { f.items[s+"/"+a] = v; return nil }
func (f *cliFakeStore) Delete(s, a string) error    { delete(f.items, s+"/"+a); return nil }
func (f *cliFakeStore) List(string) ([]Item, error) { return f.list, nil }

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	func() {
		defer func() { os.Stdout = old; w.Close() }()
		fn()
	}()
	return <-done
}

// viaCobra runs args through the real tree, and hands the translated argv to
// the same handler runLegacy would pick (selectStore is bypassed so the fake
// backend stays installed).
func viaCobra(t *testing.T, store Store, handlers map[string]func(), args ...string) string {
	t.Helper()
	oldStore, oldRun, oldArgs := currentStore, legacyRun, os.Args
	currentStore = store
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	legacyRun = func(argv []string) {
		os.Args = append([]string{"omaseal"}, argv...)
		h, ok := handlers[argv[0]]
		if !ok {
			t.Fatalf("no test handler for %q", argv[0])
		}
		h()
	}
	t.Cleanup(func() { currentStore, legacyRun, os.Args = oldStore, oldRun, oldArgs })
	return captureStdout(t, func() {
		root := newRootCmd()
		root.SilenceErrors, root.SilenceUsage = true, true
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	})
}

// A secret is printed raw: no newline added, no styling, no status line —
// whichever spelling reached the handler.
func TestSecretValuesPrintRawToStdout(t *testing.T) {
	const secret = "sk-test-0123456789 with spaces\tand\ttabs"
	fs := &cliFakeStore{items: map[string]string{"svc/acct": secret}}
	handlers := map[string]func(){"get": handleGet, "resolve": handleResolve}
	for _, args := range [][]string{
		{"get", "svc", "acct"},
		{"get", "omaseal://svc/acct"},
		{"get", "--resolve", "svc", "acct"},
		{"resolve", "svc", "acct"},
	} {
		if got := viaCobra(t, fs, handlers, args...); got != secret {
			t.Errorf("omaseal %v printed %q, want exactly the secret %q", args, got, secret)
		}
	}
}

func TestSetAndDelPrintOkOnPipe(t *testing.T) {
	fs := &cliFakeStore{items: map[string]string{"svc/acct": "v"}}
	handlers := map[string]func(){"del": handleDel}
	for _, name := range []string{"rm", "del", "delete"} {
		fs.items["svc/acct"] = "v"
		if got := viaCobra(t, fs, handlers, name, "svc", "acct"); got != "ok\n" {
			t.Errorf("omaseal %s stdout = %q, want %q", name, got, "ok\n")
		}
		if _, still := fs.items["svc/acct"]; still {
			t.Errorf("omaseal %s did not delete", name)
		}
	}
}

func TestListPlainAndJSONAreStable(t *testing.T) {
	now := time.Now()
	fs := &cliFakeStore{list: []Item{
		{Service: "openrouter", Account: "default", Label: "OpenRouter key", CreatedAt: now, UpdatedAt: now, Owned: true},
		{Service: "gh", Account: "token", Label: "GitHub", CreatedAt: now, UpdatedAt: now, Owned: true},
	}}
	handlers := map[string]func(){"list": handleList}

	wantPlain := "SERVICE     ACCOUNT  LABEL\nopenrouter  default  OpenRouter key\ngh          token    GitHub\n"
	for _, name := range []string{"ls", "list"} {
		got := viaCobra(t, fs, handlers, name)
		// Any later sort is the backend's business; compare as a set of lines.
		gl, wl := strings.Split(strings.TrimSpace(got), "\n"), strings.Split(strings.TrimSpace(wantPlain), "\n")
		sort.Strings(gl)
		sort.Strings(wl)
		if !reflect.DeepEqual(gl, wl) {
			t.Errorf("omaseal %s plain output drifted:\n got %q\nwant %q", name, got, wantPlain)
		}
	}

	for _, name := range []string{"ls", "list"} {
		got := viaCobra(t, fs, handlers, name, "--json")
		var items []Item
		if err := json.Unmarshal([]byte(got), &items); err != nil || len(items) != 2 {
			t.Errorf("omaseal %s --json: err=%v items=%d\n%s", name, err, len(items), got)
		}
		if strings.Count(got, "\n") != 1 {
			t.Errorf("omaseal %s --json must be one line, got %q", name, got)
		}
	}
}

func TestPrintErrorKeepsHistoricPlainFormat(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	printError("retrieving secret: ", errors.New("boom"))
	w.Close()
	os.Stderr = old
	b, _ := io.ReadAll(r)
	want := "error: retrieving secret: boom (code: unknown_error, help: omaseal doctor)\n"
	if string(b) != want {
		t.Fatalf("printError on a pipe = %q, want %q", b, want)
	}
}

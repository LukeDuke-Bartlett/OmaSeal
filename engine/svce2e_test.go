package main

// End-to-end conformance: the REAL omaseal subprocess serves the REAL
// secret-tool over a private bus. This is the suite's ground truth — it
// exercises libsecret's actual wire behavior (OpenSession, SearchItems,
// Secret transport) rather than our own client.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// svcE2EEnv builds the hermetic environment the provider subprocess and
// clients share: private bus + isolated store/runtime/config dirs.
type svcE2EEnv struct {
	bin     string
	bus     *svcTestBus
	state   string // XDG_STATE_HOME
	runtime string // XDG_RUNTIME_DIR
	config  string // XDG_CONFIG_HOME
	home    string
}

func newSvcE2EEnv(t *testing.T) *svcE2EEnv {
	t.Helper()
	if _, err := exec.LookPath("secret-tool"); err != nil {
		t.Skip("secret-tool (libsecret-tools) not installed")
	}
	root := t.TempDir()
	env := &svcE2EEnv{
		bin:     filepath.Join(root, "omaseal"),
		bus:     newSvcTestBus(t),
		state:   filepath.Join(root, "state"),
		runtime: filepath.Join(root, "run"),
		config:  filepath.Join(root, "config"),
		home:    root,
	}
	// Build once per test — the binary under test must be the current tree,
	// not whatever happens to be installed.
	build := exec.Command("go", "build", "-o", env.bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build omaseal: %v\n%s", err, out)
	}
	return env
}

func (e *svcE2EEnv) env() []string {
	return []string{
		"HOME=" + e.home,
		"XDG_STATE_HOME=" + e.state,
		"XDG_RUNTIME_DIR=" + e.runtime,
		"XDG_CONFIG_HOME=" + e.config,
		"XDG_DATA_HOME=" + filepath.Join(e.home, "data"),
		"DBUS_SESSION_BUS_ADDRESS=" + e.bus.addr,
		"OMASEAL_GUI_PROMPT=off",
		"PATH=" + os.Getenv("PATH"),
	}
}

// initStore writes identity.age + identity.pub directly — the TTY init
// prompt can't run in a test. Equivalent to `omaseal set` first-touch.
func (e *svcE2EEnv) initStore(t *testing.T) (storeDir string) {
	t.Helper()
	storeDir = filepath.Join(e.state, "omaseal", "native")
	if err := os.MkdirAll(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapNativeIdentity(id, "e2e-pass")
	if err != nil {
		t.Fatal(err)
	}
	for name, blob := range map[string][]byte{
		nativeIdentityFile: wrapped,
		nativePubFile:      []byte(id.Recipient().String() + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(storeDir, name), blob, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return storeDir
}

// unlockStore writes the CLI session files the daemon adopts (file-derived
// provenance) — the equivalent of `omaseal agent unlock` in-process.
func (e *svcE2EEnv) unlockStore(t *testing.T) {
	t.Helper()
	runtimeDir := filepath.Join(e.runtime, agentConfigDirName)
	s := newNativeStoreAt(filepath.Join(e.state, "omaseal", "native"), runtimeDir)
	if err := s.unlockIdentity("e2e-pass", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("unlock: %v", err)
	}
}

// serve starts the provider subprocess and blocks until it owns the name.
func (e *svcE2EEnv) serve(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(e.bin, "provider", "serve")
	cmd.Env = e.env()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("serve start: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	conn := e.bus.connect(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var unique string
		if err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0,
			svcBusName).Store(&unique); err == nil && unique != "" {
			return cmd
		}
		if time.Now().After(deadline) {
			t.Fatal("provider did not claim the name in 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *svcE2EEnv) secretTool(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("secret-tool", args...)
	cmd.Env = e.env()
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("secret-tool %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestSvcE2ESecretToolRoundTrip(t *testing.T) {
	env := newSvcE2EEnv(t)
	storeDir := env.initStore(t)
	env.unlockStore(t)
	env.serve(t)

	// store → lookup → search → clear, all through real libsecret.
	env.secretTool(t, "s3cret-e2e", "store", "--label=e2e item", "purpose", "e2e", "acct", "demo")

	got := env.secretTool(t, "", "lookup", "purpose", "e2e", "acct", "demo")
	if got != "s3cret-e2e" {
		t.Fatalf("lookup = %q, want s3cret-e2e", got)
	}

	found := env.secretTool(t, "", "search", "--all", "purpose", "e2e")
	// search --all prints [<item-id>] headers, not full paths. The item's
	// label must be the client-supplied one — the index owns labels, not
	// the synthesized native-store key.
	if !strings.Contains(found, "label = e2e item") {
		t.Fatalf("search found no item: %q", found)
	}
	if !strings.Contains(found, "attribute.acct = demo") {
		t.Fatalf("search missing attributes: %q", found)
	}

	// Native-store reconciliation: the bus-created item must be a real row
	// with a synthetic dbus/<hash> key.
	raw, err := os.ReadFile(filepath.Join(storeDir, nativeStoreFile))
	if err != nil {
		t.Fatalf("store.json: %v", err)
	}
	if !strings.Contains(string(raw), "dbus/") {
		t.Fatalf("native store missing synthetic dbus/ row: %s", raw)
	}

	env.secretTool(t, "", "clear", "purpose", "e2e", "acct", "demo")

	// After delete, the store row must be swept on next reconcile — drive
	// one with a search, then re-read.
	env.secretTool(t, "", "search", "--all", "purpose", "e2e")
	raw, err = os.ReadFile(filepath.Join(storeDir, nativeStoreFile))
	if err != nil {
		t.Fatalf("store.json after clear: %v", err)
	}
	if strings.Contains(string(raw), "dbus/") {
		t.Fatalf("cleared item still in native store: %s", raw)
	}
}

func TestSvcE2EServeRefusesContention(t *testing.T) {
	env := newSvcE2EEnv(t)
	env.initStore(t)
	env.serve(t)

	// A second serve on the same bus must exit non-zero, not queue.
	cmd := exec.Command(env.bin, "provider", "serve")
	cmd.Env = env.env()
	if err := cmd.Run(); err == nil {
		t.Fatal("second serve exited 0 — it must refuse a foreign owner")
	}
}

func TestSvcE2EServeRefusesUninitializedStore(t *testing.T) {
	env := newSvcE2EEnv(t)
	// No initStore — serve must fail fast rather than wedge on prompts.
	cmd := exec.Command(env.bin, "provider", "serve")
	cmd.Env = env.env()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("serve on uninitialized store must fail")
	}
	if !strings.Contains(string(out), "not initialized") {
		t.Fatalf("unexpected error: %s", out)
	}
}

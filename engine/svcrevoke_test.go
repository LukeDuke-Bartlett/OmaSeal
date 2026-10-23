package main

// Revocation/lifecycle coverage for the provider daemon: prompt Completed
// payloads, Dismiss cancellation, prompt-identity revocation (marker gone,
// TTL), Service.Lock unlinking the CLI session, mode-lock gate parity, and
// the wire signals libsecret clients key on.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/godbus/dbus/v5"
)

// newRevokeDaemon extends newSvcTestDaemon with a controlled clock.
func newRevokeDaemon(t *testing.T, bus *svcTestBus) (*svcDaemon, *time.Time) {
	t.Helper()
	now := time.Now().UTC()
	d := newSvcTestDaemon(t, bus)
	d.now = func() time.Time { return now }
	return d, &now
}

// svcSignals subscribes a client conn to every signal the daemon may emit.
func svcSignals(t *testing.T, conn *dbus.Conn) chan *dbus.Signal {
	t.Helper()
	if err := conn.AddMatchSignal(); err != nil {
		t.Fatalf("add match: %v", err)
	}
	ch := make(chan *dbus.Signal, 16)
	conn.Signal(ch)
	return ch
}

// drainSignals collects signals for a short window and returns them.
func drainSignals(ch chan *dbus.Signal) []*dbus.Signal {
	var out []*dbus.Signal
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case s := <-ch:
			out = append(out, s)
		case <-deadline:
			return out
		}
	}
}

func hasSignal(sigs []*dbus.Signal, name string, path dbus.ObjectPath) bool {
	for _, s := range sigs {
		if strings.HasSuffix(s.Name, name) && s.Path == path {
			return true
		}
	}
	return false
}

// --- #7: Prompt.Completed payload ----------------------------------------

func TestSvcPromptCompletedEchoesObjects(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)
	client := bus.connect(t)
	sigs := svcSignals(t, client)

	objects := []dbus.ObjectPath{svcCollectionPath()}
	path, derr := d.mintPrompt(":1.42", "test", objects, func(ctx context.Context) ([]dbus.ObjectPath, error) {
		return objects, nil
	})
	if derr != nil {
		t.Fatalf("mint: %v", derr)
	}
	if err := d.drivePrompt(path, ":1.42"); err != nil {
		t.Fatalf("drive: %v", err)
	}

	var got *dbus.Signal
	deadline := time.After(3 * time.Second)
	for got == nil {
		select {
		case s := <-sigs:
			if s.Name == "org.freedesktop.Secret.Prompt.Completed" {
				got = s
			}
		case <-deadline:
			t.Fatal("no Completed signal")
		}
	}
	if len(got.Body) != 2 {
		t.Fatalf("Completed body = %v", got.Body)
	}
	if dismissed, ok := got.Body[0].(bool); !ok || dismissed {
		t.Fatalf("dismissed = %v, want false", got.Body[0])
	}
	var echoed []dbus.ObjectPath
	if err := dbus.Store([]interface{}{got.Body[1].(dbus.Variant).Value()}, &echoed); err != nil {
		t.Fatalf("result decode: %v", err)
	}
	if len(echoed) != 1 || echoed[0] != svcCollectionPath() {
		t.Fatalf("Completed result = %v, want [%s]", echoed, svcCollectionPath())
	}
	// Prompt object is swept.
	d.mu.Lock()
	_, still := d.prompts[path]
	d.mu.Unlock()
	if still {
		t.Fatal("prompt object not swept after Completed")
	}
}

func TestSvcPromptOpErrorIsDismissed(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)
	client := bus.connect(t)
	sigs := svcSignals(t, client)

	path, derr := d.mintPrompt(":1.42", "test", nil, func(context.Context) ([]dbus.ObjectPath, error) {
		return nil, fmt.Errorf("wrong passphrase")
	})
	if derr != nil {
		t.Fatalf("mint: %v", derr)
	}
	if err := d.drivePrompt(path, ":1.42"); err != nil {
		t.Fatalf("drive: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case s := <-sigs:
			if s.Name != "org.freedesktop.Secret.Prompt.Completed" {
				continue
			}
			if dismissed, ok := s.Body[0].(bool); !ok || !dismissed {
				t.Fatalf("op error must report dismissed=true, got %v", s.Body[0])
			}
			return
		case <-deadline:
			t.Fatal("no Completed signal")
		}
	}
}

// --- #24: Dismiss cancels the in-flight op --------------------------------

func TestSvcDismissCancelsInFlightOp(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)
	client := bus.connect(t)
	sigs := svcSignals(t, client)

	opStarted := make(chan struct{})
	opDone := make(chan error, 1)
	path, derr := d.mintPrompt(":1.42", "test", nil, func(ctx context.Context) ([]dbus.ObjectPath, error) {
		close(opStarted)
		select {
		case <-ctx.Done():
			opDone <- ctx.Err()
			return nil, ctx.Err()
		case <-time.After(30 * time.Second):
			opDone <- nil
			return nil, nil
		}
	})
	if derr != nil {
		t.Fatalf("mint: %v", derr)
	}
	if err := d.drivePrompt(path, ":1.42"); err != nil {
		t.Fatalf("drive: %v", err)
	}
	<-opStarted

	if err := d.dismissPrompt(path, ":1.42"); err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	select {
	case err := <-opDone:
		if err != context.Canceled {
			t.Fatalf("op saw %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight op not cancelled by Dismiss")
	}

	// Completed must carry dismissed=true.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case s := <-sigs:
			if s.Name == "org.freedesktop.Secret.Prompt.Completed" {
				if dismissed, ok := s.Body[0].(bool); !ok || !dismissed {
					t.Fatalf("dismissed = %v, want true", s.Body[0])
				}
				return
			}
		case <-deadline:
			t.Fatal("no Completed after dismiss")
		}
	}
}

// --- #8: Service.Lock unlinks the live CLI session -------------------------

func TestSvcLockUnlinksCliSession(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)

	// Mint an identity + file-derived session artifacts in the store's
	// runtime dir — the shape a live `omaseal agent unlock` leaves.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	d.store.identity.Store(id)
	sessJSON := filepath.Join(d.store.runtimeDir, nativeSessJSONFile)
	sessAge := filepath.Join(d.store.runtimeDir, nativeSessAgeFile)
	for _, p := range []string{sessJSON, sessAge} {
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	d.lockDaemon()

	if d.store.identity.Load() != nil {
		t.Fatal("identity still held after lock")
	}
	for _, p := range []string{sessJSON, sessAge} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("session file %s still present after lock", p)
		}
	}
	// And the locked check stays locked — nothing to re-adopt.
	if !d.locked() {
		t.Fatal("daemon re-adopted an identity after Lock")
	}
}

// --- #9: prompt-identity revocation ----------------------------------------

// armPromptIdentity puts the daemon in the prompt-derived-unlocked state:
// identity in memory, provenance flag set, marker file on disk.
func armPromptIdentity(t *testing.T, d *svcDaemon, ttl time.Duration) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	d.store.identity.Store(id)
	d.promptIdentity = true
	d.promptExpiry = d.now().Add(ttl)
	marker := svcUnlockEpochPath()
	if err := writeFileMode(marker, []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	return marker
}

func TestSvcPromptIdentityMarkerGoneRelocks(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)
	marker := armPromptIdentity(t, d, time.Hour)

	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if !d.locked() {
		t.Fatal("daemon still unlocked after marker removal")
	}
	if d.promptIdentity {
		t.Fatal("promptIdentity flag not cleared")
	}
}

func TestSvcPromptIdentityTTLRelocks(t *testing.T) {
	bus := newSvcTestBus(t)
	d, now := newRevokeDaemon(t, bus)
	armPromptIdentity(t, d, time.Hour)

	*now = now.Add(2 * time.Hour) // step the controlled clock past TTL
	if !d.locked() {
		t.Fatal("daemon still unlocked after prompt TTL")
	}
}

// --- #6: mode lock denies live sessions ------------------------------------

func TestSvcModeLockDeniesLiveSession(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)

	// Write an ask-mode policy, open a session, then flip to lock: the
	// already-open session must not keep reading.
	cfg := filepath.Join(t.TempDir(), agentConfigDirName)
	if err := os.MkdirAll(cfg, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(cfg))
	pol := filepath.Join(cfg, agentPolicyFile)
	writePol := func(mode string) {
		t.Helper()
		if err := os.WriteFile(pol, []byte(fmt.Sprintf(`{"mode":%q,"session_minutes":15}`, mode)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePol("ask")

	// Arm the daemon so reads pass the locked() gate too.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	d.store.identity.Store(id)
	d.promptIdentity = true
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if err := writeFileMode(svcUnlockEpochPath(), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	d.promptExpiry = d.now().Add(time.Hour)

	client := bus.connect(t)
	obj := client.Object(svcBusName, svcBasePath)
	var out dbus.Variant
	var sessionPath dbus.ObjectPath
	if err := obj.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&out, &sessionPath); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	writePol("lock")

	sessObj := client.Object(svcBusName, sessionPath)
	call := sessObj.Call("org.freedesktop.Secret.Session.Close", 0)
	_ = call // Close itself should still work or fail — not the assertion.
	// The gate must deny secret reads AND the whole Properties surface.
	svcObj := client.Object(svcBusName, svcBasePath)
	err = svcObj.Call("org.freedesktop.Secret.Service.GetSecrets", 0,
		[]dbus.ObjectPath{svcCollectionPath() + "/nope"}, sessionPath).Store()
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("GetSecrets under mode lock = %v, want AccessDenied(locked)", err)
	}
	var v dbus.Variant
	err = svcObj.Call("org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.Secret.Collection", "Label").Store(&v)
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("Properties.Get under mode lock = %v, want AccessDenied(locked)", err)
	}
}

// --- #4/#20: wire signals ---------------------------------------------------

func TestSvcItemSignalsEmitted(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)
	client := bus.connect(t)
	sigs := svcSignals(t, client)

	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/abc123")
	d.emitItemCreated(itemPath)
	d.emitItemDeleted(itemPath)
	d.emitPropsChanged(svcCollectionPath(), "org.freedesktop.Secret.Collection",
		map[string]dbus.Variant{"Locked": dbus.MakeVariant(true)})

	got := drainSignals(sigs)
	if !hasSignal(got, "ItemCreated", svcCollectionPath()) {
		t.Fatalf("no ItemCreated on collection: %v", got)
	}
	if !hasSignal(got, "ItemDeleted", svcCollectionPath()) {
		t.Fatalf("no ItemDeleted on collection: %v", got)
	}
	if !hasSignal(got, "PropertiesChanged", svcCollectionPath()) {
		t.Fatalf("no PropertiesChanged on collection: %v", got)
	}
}

// --- #3: items.json round-trip ----------------------------------------------

func TestSvcIndexSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), svcIndexFile)
	idx := &svcIndex{
		path:  path,
		Items: map[string]*svcItem{},
	}
	now := time.Now().UTC().Truncate(time.Second)
	idx.Items["/org/freedesktop/secrets/collection/login/aa"] = &svcItem{
		Path:    "/org/freedesktop/secrets/collection/login/aa",
		Key:     "svc\x00acct",
		Label:   "my label",
		Attrs:   map[string]string{"service": "svc", "account": "acct"},
		Created: now, Modified: now,
	}
	if err := idx.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := loadSvcIndex(path)
	row, ok := got.Items["/org/freedesktop/secrets/collection/login/aa"]
	if !ok {
		t.Fatalf("load lost the item — index did not round-trip: %v", got.Items)
	}
	if row.Label != "my label" || row.Key != "svc\x00acct" {
		t.Fatalf("row = %+v", row)
	}
	if !row.Created.Equal(now) {
		t.Fatalf("created = %v, want %v", row.Created, now)
	}
}

// --- #2: reconcile preserves index-owned metadata ---------------------------

func TestSvcReconcilePreservesClientLabel(t *testing.T) {
	bus := newSvcTestBus(t)
	d, _ := newRevokeDaemon(t, bus)

	// Init the store and create a row with the CLI's synthesized label.
	oldTTY := stdinIsTTY
	stdinIsTTY = func() bool { return true }
	t.Cleanup(func() { stdinIsTTY = oldTTY })
	d.store.prompt = func(string) (string, error) { return "pass", nil }
	if err := d.store.Set("svc", "acct", "secret"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	// First reconcile seeds the index from the store row.
	if err := d.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var path string
	for p := range d.index.Items {
		path = p
	}
	if path == "" {
		t.Fatal("reconcile produced no index row")
	}

	// A client relabels it — the index is authoritative for Label.
	d.index.Items[path].Label = "client label"

	// Reconcile again: the index-owned label must survive.
	if err := d.reconcile(); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if got := d.index.Items[path].Label; got != "client label" {
		t.Fatalf("client label stomped: %q", got)
	}
}

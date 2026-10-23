package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// svcTestBus spawns a private dbus-daemon for one test — the conformance
// suite's fixture. Deterministic: readiness is read from the daemon's own
// --print-address line, never slept on.
type svcTestBus struct {
	addr string
	cmd  *exec.Cmd
}

func newSvcTestBus(t *testing.T) *svcTestBus {
	t.Helper()
	cmd := exec.Command("dbus-daemon", "--session", "--print-address=1", "--print-pid=1", "--nofork")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("dbus-daemon stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("dbus-daemon unavailable: %v", err)
	}
	scan := bufio.NewScanner(stdout)
	if !scan.Scan() {
		_ = cmd.Process.Kill()
		t.Fatalf("dbus-daemon printed no address")
	}
	bus := &svcTestBus{addr: strings.TrimSpace(scan.Text()), cmd: cmd}
	t.Cleanup(func() { _ = bus.cmd.Process.Kill(); _ = bus.cmd.Wait() })
	return bus
}

// connect dials the private bus.
func (b *svcTestBus) connect(t *testing.T) *dbus.Conn {
	t.Helper()
	conn, err := svcConnect(b.addr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// newSvcTestDaemon starts a daemon on the private bus with a temp native
// store — never touches real state. Returns when the name is claimed.
func newSvcTestDaemon(t *testing.T, bus *svcTestBus) *svcDaemon {
	t.Helper()
	conn, err := svcConnect(bus.addr)
	if err != nil {
		t.Fatalf("daemon connect: %v", err)
	}
	if err := svcClaimName(conn); err != nil {
		t.Fatalf("daemon claim: %v", err)
	}
	d := &svcDaemon{
		conn:     conn,
		store:    newNativeStoreAt(t.TempDir(), t.TempDir()),
		sessions: map[dbus.ObjectPath]*svcSession{},
		prompts:  map[dbus.ObjectPath]*svcPrompt{},
		index:    &svcIndex{Items: map[string]*svcItem{}, path: filepath.Join(t.TempDir(), svcIndexFile)},
		lostName: make(chan struct{}),
		now:      func() time.Time { return time.Now().UTC() },
	}
	if err := d.installObjects(); err != nil {
		t.Fatalf("install objects: %v", err)
	}
	if err := d.watchNames(); err != nil {
		t.Fatalf("watch names: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return d
}

// waitLost blocks until the daemon observes the name lost (event-driven).
func waitLost(t *testing.T, d *svcDaemon) {
	t.Helper()
	select {
	case <-d.lostName:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not observe name loss")
	}
}

func TestSvcClaimNameContention(t *testing.T) {
	bus := newSvcTestBus(t)
	first := bus.connect(t)
	if err := svcClaimName(first); err != nil {
		t.Fatalf("first claim must win: %v", err)
	}
	second := bus.connect(t)
	err := svcClaimName(second)
	if err == nil {
		t.Fatal("second claim must refuse, not queue")
	}
	if !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("refusal must name the owner: %v", err)
	}
	// Release frees it for a later claimer.
	if _, err := first.ReleaseName(svcBusName); err != nil {
		t.Fatal(err)
	}
	if err := svcClaimName(second); err != nil {
		t.Fatalf("post-release claim: %v", err)
	}
}

func TestSvcDaemonExitsOnNameLoss(t *testing.T) {
	bus := newSvcTestBus(t)
	d := newSvcTestDaemon(t, bus)

	// A foreign client takes the name with replacement — impossible under
	// DoNotQueue for the claim itself, but ReleaseName then claim simulates
	// the daemon observing a foreign owner appear.
	rival := bus.connect(t)
	if _, err := d.conn.ReleaseName(svcBusName); err != nil {
		t.Fatal(err)
	}
	if err := svcClaimName(rival); err != nil {
		t.Fatalf("rival claim: %v", err)
	}
	waitLost(t, d)
}

func TestSvcPeerInfoSelf(t *testing.T) {
	bus := newSvcTestBus(t)
	conn := bus.connect(t)
	self := conn.Names()[0]
	uid, pid, exe, err := svcPeerInfo(conn, self)
	if err != nil {
		t.Fatalf("peercred: %v", err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("uid %d, want %d", uid, os.Getuid())
	}
	if pid != uint32(os.Getpid()) {
		t.Fatalf("pid %d, want %d", pid, os.Getpid())
	}
	if exe == "" || exe == "unknown" {
		t.Fatalf("exe unresolved: %q", exe)
	}
}

func TestSvcReapSender(t *testing.T) {
	bus := newSvcTestBus(t)
	d := newSvcTestDaemon(t, bus)

	// Plant sessions owned by a fake unique name, then verify the reap path
	// — driven directly since unit-of-work is the GC map logic.
	ghost := ":1.4242"
	p0 := dbus.ObjectPath("/org/freedesktop/secrets/session/0")
	p1 := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	d.mu.Lock()
	d.sessions[p0] = &svcSession{owner: ghost, created: d.now()}
	d.sessions[p1] = &svcSession{owner: ":9.9", created: d.now()}
	d.mu.Unlock()

	d.reapSender(ghost)

	d.mu.Lock()
	_, gone := d.sessions[p0]
	_, kept := d.sessions[p1]
	d.mu.Unlock()
	if gone || !kept {
		t.Fatalf("reap: ghost gone=%v kept=%v", gone, kept)
	}
}

func TestSvcConnectRejectsEmptyAddress(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	if _, err := svcConnect(""); err == nil {
		t.Fatal("empty address must error")
	}
}

func TestSvcPeerPIDNonexistent(t *testing.T) {
	bus := newSvcTestBus(t)
	conn := bus.connect(t)
	if _, err := svcPeerPID(conn, ":1.99999"); err == nil {
		t.Fatal("bogus unique name must error")
	}
}

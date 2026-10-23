package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// stubProviderSideEffects keeps enable/disable off the real systemctl and
// ambient bus — the tests assert file artifacts, not the live session.
func stubProviderSideEffects(t *testing.T) {
	t.Helper()
	oldSys, oldDial := svcSystemctl, svcConnectAmbient
	svcSystemctl = func(args ...string) ([]byte, error) { return nil, nil }
	svcConnectAmbient = func() (*dbus.Conn, error) {
		return nil, fmt.Errorf("no ambient bus in test")
	}
	t.Cleanup(func() { svcSystemctl, svcConnectAmbient = oldSys, oldDial })
}

func TestProviderEnableWritesActivationAndUnit(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubProviderSideEffects(t)

	if err := providerEnable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	act, err := os.ReadFile(svcActivationPath())
	if err != nil {
		t.Fatalf("activation file: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	for _, want := range []string{"Name=org.freedesktop.secrets", "SystemdService=omaseal-provider.service", "Exec=" + exe + " provider serve"} {
		if !strings.Contains(string(act), want) {
			t.Errorf("activation missing %q", want)
		}
	}
	unit, err := os.ReadFile(svcUnitPath())
	if err != nil {
		t.Fatalf("unit file: %v", err)
	}
	for _, want := range []string{"Type=dbus", "BusName=org.freedesktop.secrets", "LimitCORE=0", "ExecStart=" + exe + " provider serve"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit missing %q", want)
		}
	}
}

func TestProviderDisableRemovesFiles(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubProviderSideEffects(t)

	if err := providerEnable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := providerDisable(); err != nil {
		t.Fatalf("disable: %v", err)
	}
	for _, p := range []string{svcActivationPath(), svcUnitPath()} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still present after disable", p)
		}
	}
}

func TestProviderDisableIdempotent(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubProviderSideEffects(t)
	if err := providerDisable(); err != nil {
		t.Fatalf("disable with nothing installed: %v", err)
	}
}

func TestSvcOwnerIsOursSelfClaim(t *testing.T) {
	bus := newSvcTestBus(t)
	conn := bus.connect(t)
	// The test process claiming the name makes us the owner — pid/exe
	// resolution should identify this binary as ours.
	if err := svcClaimName(conn); err != nil {
		t.Fatalf("claim: %v", err)
	}
	ours, owner, _ := svcOwnerIsOurs(conn)
	if !ours {
		t.Fatalf("owner %s should resolve as ours", owner)
	}
	if !strings.Contains(owner, "pid=") {
		t.Errorf("owner desc missing pid: %s", owner)
	}
}

func TestSvcOwnerIsOursForeignAndUnowned(t *testing.T) {
	bus := newSvcTestBus(t)
	conn := bus.connect(t)
	ours, owner, _ := svcOwnerIsOurs(conn)
	if ours {
		t.Fatal("unowned name resolved as ours")
	}
	if owner != "" {
		t.Fatalf("unowned name gave owner %q", owner)
	}
}

func TestSvcActivationUnderXDGDataHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	want := filepath.Join(dir, "dbus-1", "services", "org.freedesktop.secrets.service")
	if got := svcActivationPath(); got != want {
		t.Fatalf("activation path %q, want %q", got, want)
	}
}

// TestContribUnitMatchesTemplate pins contrib/omaseal-provider.service (the
// file the package installs) to the unit body `provider enable` writes —
// single-sourcing the unit facts so the two install paths can't drift.
func TestContribUnitMatchesTemplate(t *testing.T) {
	raw, err := os.ReadFile("../contrib/omaseal-provider.service")
	if err != nil {
		t.Skipf("contrib unit not present: %v", err)
	}
	// The contrib file may carry comment lines the embedded template omits;
	// the unit facts must be byte-identical once those are stripped.
	var body []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		body = append(body, line)
	}
	got := strings.TrimSpace(strings.Join(body, "\n")) + "\n"
	if got != svcUnitContents {
		t.Fatalf("contrib unit drifted from svcUnitContents:\n--- contrib ---\n%s\n--- embedded ---\n%s", got, svcUnitContents)
	}
}

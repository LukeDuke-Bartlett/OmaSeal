package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
)

// Provider activation files (U6). Two artifacts make the daemon the bus's
// Secret Service for this user:
//
//	dbus-1 services file — bus-activation entry; `SystemdService=` hands
//	  startups to the user unit under systemd, `Exec=` is the fallback for
//	  non-systemd sessions.
//	systemd user unit — Type=dbus pins readiness to the name claim;
//	  LimitCORE=0 keeps vault material out of crash dumps.
//
// The activation file lives under ~/.local/share/dbus-1/services so it
// shadows — not replaces — the system-wide gnome-keyring entry.

const svcActivationContents = `[D-BUS Service]
Name=org.freedesktop.secrets
Exec=/usr/bin/omaseal provider serve
SystemdService=omaseal-provider.service
`

const svcUnitContents = `[Unit]
Description=OmaSeal Secret Service provider
Documentation=https://github.com/duketopceo/OmaSeal

[Service]
Type=dbus
BusName=org.freedesktop.secrets
ExecStart=/usr/bin/omaseal provider serve
LimitCORE=0
Restart=on-failure

[Install]
WantedBy=default.target
`

// svcXDGDir resolves an XDG base dir with the spec fallback — the single
// home for the env-or-~ pattern the provider paths all share.
func svcXDGDir(envKey string, fallbackParts ...string) string {
	if base := os.Getenv(envKey); base != "" {
		return base
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{home}, fallbackParts...)...)
}

func svcActivationPath() string {
	return filepath.Join(svcXDGDir("XDG_DATA_HOME", ".local", "share"), "dbus-1", "services", "org.freedesktop.secrets.service")
}

func svcUnitPath() string {
	return filepath.Join(svcXDGDir("XDG_CONFIG_HOME", ".config"), "systemd", "user", "omaseal-provider.service")
}

// svcSystemctl is the systemctl seam — tests stub it so enable/disable
// never execs the real user's service manager.
var svcSystemctl = func(args ...string) ([]byte, error) {
	cmd := exec.Command("systemctl", args...)
	return cmd.CombinedOutput()
}

// svcConnectAmbient dials the session bus — a seam so tests never touch
// the real user's Secret Service owner.
var svcConnectAmbient = func() (*dbus.Conn, error) {
	return svcConnect("")
}

func svcDaemonReload() error {
	_, err := svcSystemctl("--user", "daemon-reload")
	return err
}

func svcStopUnit() error {
	out, err := svcSystemctl("--user", "stop", "omaseal-provider.service")
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// svcActivationIsOurs reports whether the installed activation file Execs an
// omaseal binary — compared by basename so an omaseal at any prefix counts.
// An installed-but-inactive omaseal activation can take the name mid-migrate
// (the moment the foreign owner exits or a call activates us), so guards
// that check only the live owner miss it.
func svcActivationIsOurs() bool {
	data, err := os.ReadFile(svcActivationPath())
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Exec=") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Exec="))
		if len(fields) > 0 && filepath.Base(fields[0]) == "omaseal" {
			return true
		}
	}
	return false
}

// svcOwnerIsOurs reports whether the name's current owner is an omaseal
// binary — resolved via pid → /proc/<pid>/exe against os.Executable, so a
// foreign process claiming the name never counts.
func svcOwnerIsOurs(conn *dbus.Conn) (ours bool, owner string, pid uint32) {
	var unique string
	if err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, svcBusName).Store(&unique); err != nil {
		return false, "", 0
	}
	p, err := svcPeerPID(conn, unique)
	if err != nil {
		return false, unique, 0
	}
	self, _ := os.Executable()
	target, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", p))
	ours = target != "" && self != "" && target == self
	return ours, fmt.Sprintf("%s pid=%d exe=%s", unique, p, filepath.Base(target)), p
}

// svcFileIsOurs reports whether an existing file at path is omaseal-authored
// (its Exec/unit lines invoke `provider serve` — the marker survives the exe
// path substitution, unlike the binary's own name). A foreign file at one of
// these paths belongs to another provider and is never ours to remove.
func svcFileIsOurs(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(data), "provider serve")
}

// providerEnable installs the activation shadow + user unit.
func providerEnable(args []string) error {
	for _, a := range args {
		return fmt.Errorf("unknown flag %q — `omaseal provider enable` takes none", a)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	// Templates pin /usr/bin/omaseal; substitute the resolved binary so a
	// /usr/local/bin or per-user install still produces working activation.
	activation := strings.ReplaceAll(svcActivationContents, "/usr/bin/omaseal", exe)
	unit := strings.ReplaceAll(svcUnitContents, "/usr/bin/omaseal", exe)
	if err := os.MkdirAll(filepath.Dir(svcActivationPath()), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(svcUnitPath()), 0755); err != nil {
		return err
	}
	// Never clobber a foreign file at these paths — the activation name is
	// the spec's shared slot, so another provider's entry moves aside and
	// comes back on disable rather than being destroyed.
	for _, p := range []string{svcActivationPath(), svcUnitPath()} {
		if svcFileIsOurs(p) {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			bak := p + ".omaseal-bak"
			if rerr := os.Rename(p, bak); rerr != nil {
				return fmt.Errorf("foreign file at %s, backup failed: %w", p, rerr)
			}
			fmt.Printf("existing foreign file moved to %s\n", bak)
		}
	}
	if err := os.WriteFile(svcActivationPath(), []byte(activation), 0644); err != nil {
		return fmt.Errorf("activation file: %w", err)
	}
	if err := os.WriteFile(svcUnitPath(), []byte(unit), 0644); err != nil {
		return fmt.Errorf("unit file: %w", err)
	}
	if err := svcDaemonReload(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: daemon-reload failed (%v) — enable manually with `systemctl --user daemon-reload`\n", err)
	}

	// Store must exist before serve can start — init is TTY-only.
	store := newNativeStore()
	if _, err := os.Stat(storeIdentityPath(store)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: native store uninitialized — run `omaseal set` once in a terminal or the daemon will fail on activation\n")
	}

	fmt.Println("provider enabled:")
	fmt.Println("  " + svcActivationPath())
	fmt.Println("  " + svcUnitPath())

	conn, err := svcConnectAmbient()
	if err == nil {
		defer func() { _ = conn.Close() }()
		ours, owner, _ := svcOwnerIsOurs(conn)
		switch {
		case ours:
			fmt.Println("omaseal already owns " + svcBusName)
		case owner != "":
			fmt.Printf("%s is owned by %s — omaseal takes over after that process exits or `omaseal provider disable`-style stop, then next activation\n", svcBusName, owner)
		default:
			fmt.Println("name is unowned — first activation claims it")
		}
	}
	return nil
}

// providerDisable stops the unit, then removes the activation shadow so the
// next activation returns to the system provider (gnome-keyring). Only
// omaseal-authored files are removed — a foreign file is left alone, and one
// we backed up at enable is restored.
func providerDisable() error {
	if err := svcStopUnit(); err != nil {
		fmt.Fprintf(os.Stderr, "note: unit stop: %v (non-systemd session or unit inactive)\n", err)
	}
	var removed []string
	for _, p := range []string{svcActivationPath(), svcUnitPath()} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}
		if !svcFileIsOurs(p) {
			fmt.Printf("note: %s left in place — not an omaseal file\n", p)
			continue
		}
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
		removed = append(removed, p)
	}
	// Restore whatever a foreign file was moved aside as at enable.
	for _, p := range []string{svcActivationPath(), svcUnitPath()} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			continue
		}
		if rerr := os.Rename(p+".omaseal-bak", p); rerr == nil {
			fmt.Println("  restored " + p)
		}
	}
	if err := svcDaemonReload(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: daemon-reload failed (%v)\n", err)
	}
	if len(removed) == 0 {
		fmt.Println("provider was not enabled")
	} else {
		fmt.Println("provider disabled:")
		for _, p := range removed {
			fmt.Println("  removed", p)
		}
	}
	conn, err := svcConnectAmbient()
	if err == nil {
		defer func() { _ = conn.Close() }()
		ours, owner, pid := svcOwnerIsOurs(conn)
		switch {
		case ours:
			// Removing the activation file does not release a name already
			// owned: a directly Exec-activated daemon survives `systemctl
			// stop`. The owner is verified omaseal — SIGTERM is the same-UID
			// shutdown path.
			_ = syscall.Kill(int(pid), syscall.SIGTERM)
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if still, _, _ := svcOwnerIsOurs(conn); !still {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if still, _, _ := svcOwnerIsOurs(conn); still {
				return fmt.Errorf("omaseal daemon (pid %d) still owns %s — kill it manually", pid, svcBusName)
			}
			fmt.Printf("stopped omaseal daemon (pid %d)\n", pid)
		case owner != "":
			fmt.Printf("note: %s still owned by %s until that process exits\n", svcBusName, owner)
		}
	}
	return nil
}

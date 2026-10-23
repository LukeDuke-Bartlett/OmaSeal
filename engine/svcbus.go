package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// The provider daemon: OmaSeal serving org.freedesktop.secrets on the user
// session bus, backed by the native store. Design and invariants:
// docs/plans/2026-10-10-002-feat-secret-service-provider-daemon-plan.md.
//
// Load-bearing rules:
//   - Never use currentStore / selectStore — a secretservice backend would
//     recurse into this daemon. The daemon holds newNativeStore() directly.
//   - Name lifecycle is polite: RequestName(DoNotQueue), refuse contention,
//     exit on name loss.
//   - All mutable daemon state sits behind svcDaemon.mu — godbus runs every
//     method call in its own goroutine and has no recover in dispatch, so
//     handlers must not panic (svcrouter wraps calls defensively).
//   - Long waits (prompt round-trips, prompter spawns) run OFF mu so one
//     dialog cannot starve the bus.

const (
	svcBusName  = "org.freedesktop.secrets"
	svcBasePath = dbus.ObjectPath("/org/freedesktop/secrets")
)

// svcDaemon is the serving state of a `provider serve` process.
type svcDaemon struct {
	conn  *dbus.Conn
	store *nativeStore

	mu       sync.Mutex
	sessions map[dbus.ObjectPath]*svcSession
	prompts  map[dbus.ObjectPath]*svcPrompt
	index    *svcIndex

	// Prompt-derived unlock provenance (KTD2): identity held in memory
	// only, revoked by unlock-epoch marker removal, Service.Lock, or TTL.
	promptIdentity bool
	promptExpiry   time.Time

	lostName chan struct{} // closed when the well-known name is lost

	now func() time.Time
}

// svcSession is one negotiated OpenSession transport.
type svcSession struct {
	owner   string // unique bus name of the creator, e.g. ":1.42"
	uid     uint32
	codec   svcSessionCodec
	created time.Time
}

// svcConnect dials a session bus at address (env
// DBUS_SESSION_BUS_ADDRESS when empty). A private connection — never the
// shared SessionBus() handle, which would pin every in-process consumer to
// one bus.
func svcConnect(address string) (*dbus.Conn, error) {
	if address == "" {
		address = os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	}
	if address == "" {
		return nil, errors.New("no session bus address")
	}
	conn, err := dbus.Connect(address)
	if err != nil {
		return nil, fmt.Errorf("connect session bus: %w", err)
	}
	return conn, nil
}

// svcClaimName requests org.freedesktop.secrets without queuing or
// replacement. Returns the owner description when a foreign process holds
// it so the caller can report who has it.
func svcClaimName(conn *dbus.Conn) error {
	reply, err := conn.RequestName(svcBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("request name: %w", err)
	}
	switch reply {
	case dbus.RequestNameReplyPrimaryOwner, dbus.RequestNameReplyAlreadyOwner:
		return nil
	}
	owner := svcOwnerDesc(conn)
	return fmt.Errorf("%s is already owned by %s — refusing to queue for it", svcBusName, owner)
}

// svcOwnerDesc describes the current owner of the well-known name —
// delegates to the single owner→pid→exe resolver in svcOwnerIsOurs.
func svcOwnerDesc(conn *dbus.Conn) string {
	_, owner, _ := svcOwnerIsOurs(conn)
	if owner == "" {
		return "unknown owner"
	}
	return owner
}

// svcPeerUID resolves a unique sender name (":1.42") to its unix uid.
func svcPeerUID(conn *dbus.Conn, sender string) (uint32, error) {
	var uid uint32
	err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, sender).Store(&uid)
	return uid, err
}

// svcPeerPID resolves a unique sender name to its unix pid.
func svcPeerPID(conn *dbus.Conn, sender string) (uint32, error) {
	var pid uint32
	err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, sender).Store(&pid)
	return pid, err
}

// svcPeerExe resolves a pid to its executable basename for prompt/audit
// text. /proc/<pid>/exe is a symlink to the real binary.
func svcPeerExe(pid uint32) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "unknown"
	}
	return filepath.Base(exe)
}

// svcPeerInfo bundles the per-call identity: uid gate + attribution text.
func svcPeerInfo(conn *dbus.Conn, sender string) (uid, pid uint32, exe string, err error) {
	uid, err = svcPeerUID(conn, sender)
	if err != nil {
		return 0, 0, "", fmt.Errorf("sender uid: %w", err)
	}
	pid, err = svcPeerPID(conn, sender)
	if err != nil {
		return 0, 0, "", fmt.Errorf("sender pid: %w", err)
	}
	return uid, pid, svcPeerExe(pid), nil
}

// watchNames registers a NameOwnerChanged match; losing the well-known name
// closes lostName (caller exits); losing a client's unique name reaps its
// sessions and prompts. Only the bus driver may send this signal — a peer
// forging it could kill the daemon or reap live clients, so sender is
// pinned to org.freedesktop.DBus both in the match rule and the check.
func (d *svcDaemon) watchNames() error {
	call := d.conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0,
		"type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'")
	if call.Err != nil {
		return fmt.Errorf("addmatch NameOwnerChanged: %w", call.Err)
	}
	ch := make(chan *dbus.Signal, 32)
	d.conn.Signal(ch)
	go func() {
		for sig := range ch {
			if sig.Sender != "org.freedesktop.DBus" ||
				sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) != 3 {
				continue
			}
			name, _ := sig.Body[0].(string)
			newOwner, _ := sig.Body[2].(string)
			if name == svcBusName && newOwner != d.conn.Names()[0] {
				// Lost the name — to a foreign claimant or released to no
				// owner. Exit rather than linger as a shadow object surface.
				WriteLog("provider: lost %s to %s", svcBusName, newOwner)
				close(d.lostName)
				return
			}
			if newOwner == "" && name != svcBusName {
				d.reapSender(name)
			}
		}
		// The bus dropped the signal channel — the connection is gone and
		// with it the name claim. Exit rather than zombie-serve nothing.
		close(d.lostName)
	}()
	return nil
}

// reapSender drops everything a disconnected unique name owned — sessions
// die with their client; orphaned prompts complete dismissed so nobody
// waits on a dead caller.
func (d *svcDaemon) reapSender(name string) {
	var orphans []dbus.ObjectPath
	d.mu.Lock()
	for path, s := range d.sessions {
		if s.owner == name {
			delete(d.sessions, path)
		}
	}
	for path, p := range d.prompts {
		if p.owner == name {
			orphans = append(orphans, path)
		}
	}
	d.mu.Unlock()
	for _, path := range orphans {
		d.finishPrompt(path, true, nil, context.Canceled)
	}
}

// dropDumpable masks core dumps at exec — belt to the unit's LimitCORE=0
// suspenders so a daemon crash never writes vault material to disk.
func dropDumpable() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

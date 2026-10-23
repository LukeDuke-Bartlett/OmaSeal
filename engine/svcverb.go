package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// `omaseal provider` — the Secret Service provider daemon verbs.
//
//	serve     claim org.freedesktop.secrets on the session bus and serve it
//	          (D-Bus/systemd activation target — normally not run by hand)
//	status    show who owns the name and whether activation is installed
//	enable    write the D-Bus activation file + systemd user unit
//	disable   stop the daemon and remove the activation shadow
//
// The verb dispatches BEFORE selectStore() in main — the daemon serves the
// native store directly and must not die on config it never reads, nor
// recurse into a `secretservice` backend that would call itself.

func handleProvider() {
	if len(os.Args) < 3 {
		providerUsage()
		os.Exit(1)
	}
	switch os.Args[2] {
	case "serve":
		if err := providerServe(); err != nil {
			fmt.Fprintln(os.Stderr, "provider serve:", err)
			os.Exit(1)
		}
	case "status":
		if err := providerStatus(os.Args[3:]); err != nil {
			fmt.Fprintln(os.Stderr, "provider status:", err)
			os.Exit(1)
		}
	case "enable":
		if err := providerEnable(os.Args[3:]); err != nil {
			fmt.Fprintln(os.Stderr, "provider enable:", err)
			os.Exit(1)
		}
	case "disable":
		if err := providerDisable(); err != nil {
			fmt.Fprintln(os.Stderr, "provider disable:", err)
			os.Exit(1)
		}
	default:
		providerUsage()
		os.Exit(1)
	}
}

func providerUsage() {
	fmt.Fprintf(os.Stderr, `omaseal provider — Secret Service provider daemon

  omaseal provider serve     own org.freedesktop.secrets on this session bus
  omaseal provider status    show the current name owner + enabled state
  omaseal provider enable    install the activation file + systemd user unit
  omaseal provider disable   stop the daemon, remove activation files
`)
}

// providerServe is the daemon entry. It claims the name politely and serves
// until the name is lost. Startup failures are typed errors — under systemd
// the unit simply fails rather than racing a foreign owner.
func providerServe() error {
	dropDumpable()

	store := newNativeStore()
	// An uninitialized store can never satisfy a bus Prompt — init needs a
	// TTY passphrase. Fail fast so clients see ServiceUnknown instead of a
	// permanently erroring provider.
	if _, err := os.Stat(storeIdentityPath(store)); err != nil {
		return fmt.Errorf("native store not initialized (no %s) — run `omaseal set` once in a terminal first", storeIdentityPath(store))
	}

	conn, err := svcConnectAmbient()
	if err != nil {
		return err
	}

	d := &svcDaemon{
		conn:     conn,
		store:    store,
		sessions: map[dbus.ObjectPath]*svcSession{},
		prompts:  map[dbus.ObjectPath]*svcPrompt{},
		index:    loadSvcIndex(svcIndexPath()),
		lostName: make(chan struct{}),
		now:      func() time.Time { return time.Now().UTC() },
	}
	if err := d.installObjects(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("export object surface: %w", err)
	}
	if err := d.watchNames(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("name watch: %w", err)
	}
	// Claim last: no client may reach the name before the object surface
	// and the loss watch are armed.
	if err := svcClaimName(conn); err != nil {
		_ = conn.Close()
		return err
	}

	WriteLog("provider: serving %s on the session bus", svcBusName)
	<-d.lostName
	return fmt.Errorf("lost %s", svcBusName)
}

// storeIdentityPath reports the daemon's native identity file — the
// existence check that gates serve.
func storeIdentityPath(s *nativeStore) string {
	return s.dir + "/" + nativeIdentityFile
}

// providerStatus reports the name owner, enabled state, activation paths,
// and whether a running provider's environment can reach a GUI prompter.
// --json emits the same facts machine-readably for panels and scripts.
func providerStatus(args []string) error {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		default:
			return fmt.Errorf("unknown flag %q — usage: omaseal provider status [--json]", a)
		}
	}
	conn, err := svcConnectAmbient()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	var unique string
	owned := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, svcBusName).Store(&unique) == nil
	ours, ownerDesc, _ := svcOwnerIsOurs(conn)
	_, actErr := os.Stat(svcActivationPath())
	_, unitErr := os.Stat(svcUnitPath())
	enabled := actErr == nil || unitErr == nil

	if asJSON {
		out := map[string]any{
			"name":    svcBusName,
			"owned":   owned,
			"ours":    ours,
			"enabled": enabled,
		}
		if owned {
			out["owner"] = ownerDesc
		}
		if enabled {
			out["activation"] = svcActivationPath()
			out["unit"] = svcUnitPath()
		}
		enc := json.NewEncoder(os.Stdout)
		return enc.Encode(out)
	}

	if !owned {
		fmt.Println(svcBusName, "is unowned — first activation wins")
	} else {
		fmt.Printf("%s owned by %s\n", svcBusName, svcOwnerDesc(conn))
		if ours {
			svcWarnIfNoDisplay(conn, unique)
		}
	}
	if enabled {
		fmt.Println("enabled: activation/unit installed")
		fmt.Println("  " + svcActivationPath())
		fmt.Println("  " + svcUnitPath())
	} else {
		fmt.Println("not enabled — `omaseal provider enable` installs activation")
	}
	return nil
}

// svcWarnIfNoDisplay checks a running provider's environment for display
// access — without WAYLAND_DISPLAY/DISPLAY the Prompt path fails closed and
// unlock prompts silently can't render.
func svcWarnIfNoDisplay(conn *dbus.Conn, unique string) {
	pid, err := svcPeerPID(conn, unique)
	if err != nil {
		return
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return
	}
	env := string(raw)
	if !strings.Contains(env, "WAYLAND_DISPLAY=") && !strings.Contains(env, "DISPLAY=") {
		fmt.Println("warning: provider environment has no WAYLAND_DISPLAY/DISPLAY — GUI unlock prompts will fail")
	}
}

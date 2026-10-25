package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/zalando/go-keyring"
)

// envBindings collects repeatable -e/--env NAME=ref flags.
type envBindings []struct{ name, ref string }

func (e *envBindings) String() string { return "" }
func (e *envBindings) Set(v string) error {
	name, ref, ok := strings.Cut(v, "=")
	if !ok || !validEnvName(name) {
		return fmt.Errorf("want NAME=<ref> (NAME in [A-Za-z_][A-Za-z0-9_]*), got %q", v)
	}
	if ref == "" {
		return fmt.Errorf("empty reference for %s", name)
	}
	*e = append(*e, struct{ name, ref string }{name, ref})
	return nil
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' ||
			(i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// runRef resolves the ref form inside -e: omaseal://service/account, or a bare
// service/account pair. Loose charset — stored names may predate validation.
func runRef(ref string) (service, account string, err error) {
	if isOmaSealFamily(ref) {
		service, account, err = parseRef(ref, false)
		if err != nil {
			return "", "", err
		}
		if account == "" {
			return "", "", fmt.Errorf("%s needs an account: want omaseal://<service>/<account>", ref)
		}
		return service, account, nil
	}
	service, account, _ = strings.Cut(ref, "/")
	if service == "" || account == "" {
		return "", "", fmt.Errorf("malformed reference %q: want <service>/<account> or omaseal://<service>/<account>", ref)
	}
	return service, account, nil
}

// parseRunArgs splits `omaseal run` flags from the child command. Everything
// after `--` (or after the first non-flag token, so `run CMD` also works)
// belongs to the child.
func parseRunArgs(args []string) (bindings envBindings, resolve bool, cmdArgs []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return bindings, resolve, args[i+1:], nil
		case a == "--resolve":
			resolve = true
		case a == "-e" || a == "--env":
			i++
			if i >= len(args) {
				return nil, false, nil, errors.New("-e/--env needs a NAME=ref value")
			}
			if e := bindings.Set(args[i]); e != nil {
				return nil, false, nil, e
			}
		case strings.HasPrefix(a, "-e=") || strings.HasPrefix(a, "--env="):
			v := strings.SplitN(a, "=", 2)[1]
			if e := bindings.Set(v); e != nil {
				return nil, false, nil, e
			}
		case strings.HasPrefix(a, "-"):
			return nil, false, nil, fmt.Errorf("unknown flag %q", a)
		default:
			// First bare token starts the child command.
			return bindings, resolve, args[i:], nil
		}
	}
	return bindings, resolve, nil, nil
}

const runUsage = "usage: omaseal run [-e NAME=ref]... [--resolve] -- <cmd> [args]"

// injectSecrets appends resolved NAME=value pairs to env. The error names the
// binding; the exit code distinguishes malformed refs (2) from missing
// secrets (127). The child inherits the caller's full environment plus the
// injected names — later bindings shadow earlier env entries.
func injectSecrets(env []string, bindings envBindings, resolve bool) ([]string, int, error) {
	for _, b := range bindings {
		service, account, err := runRef(b.ref)
		if err != nil {
			return nil, 2, fmt.Errorf("%s: %w", b.name, err)
		}
		var v string
		if resolve {
			v, err = Resolve(context.Background(), service, account, false, false)
		} else {
			v, err = storeGet(service, account)
		}
		if err != nil {
			// Only a genuine miss is 127. A locked/unavailable keyring must
			// not masquerade as "no secret" — it tells the user to store a
			// secret that already exists.
			if errors.Is(err, keyring.ErrNotFound) || codeFromError(err) == "not_found" {
				return nil, 127, fmt.Errorf("%s: no secret for %s/%s", b.name, service, account)
			}
			return nil, 1, fmt.Errorf("%s: cannot read %s/%s: %w", b.name, service, account, err)
		}
		env = append(env, b.name+"="+v)
		// A flagged secret still injects — the child may need the old value
		// to finish its work — but the stderr warning tells whoever watches
		// the logs to rotate it.
		warnIfFlagged(service, account)
	}
	return env, 0, nil
}

// handleRun implements `omaseal run` — spawn a command with secrets injected
// into its environment so harness configs never hold the values.
//
//	omaseal run -e GITHUB_TOKEN=github/token -e KEY=omaseal://svc/acct -- <cmd> [args]
//
// Reads are Get (local keyring) by default — a spawned MCP child must never
// trigger the provider sweep or a GUI prompt. --resolve opts into the full
// fallback chain for the rare interactive case.
func handleRun() {
	// -h/--help only as the first arg — after -- it belongs to the child.
	if len(os.Args) > 2 && (os.Args[2] == "-h" || os.Args[2] == "--help") {
		fmt.Println(runUsage)
		fmt.Println("  refs: <service>/<account> or omaseal://<service>/<account>")
		fmt.Println("  -e is repeatable; reads are local keyring only unless --resolve")
		return
	}
	bindings, resolve, cmdArgs, err := parseRunArgs(os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v — %s\n", err, runUsage)
		os.Exit(2)
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "run: no command — %s\n", runUsage)
		os.Exit(2)
	}

	env, code, err := injectSecrets(os.Environ(), bindings, resolve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		os.Exit(code)
	}

	// exec(3), not exec.Command: omaseal run IS the server process image.
	// A SIGTERM/SIGINT aimed at the wrapper's PID hits the real server, the
	// exit code is the child's own, and no orphaned secret-bearing process
	// can outlive a supervisor kill.
	path, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		os.Exit(127)
	}
	if err := syscall.Exec(path, cmdArgs, env); err != nil {
		fmt.Fprintf(os.Stderr, "run: exec %s: %v\n", path, err)
		os.Exit(126)
	}
}

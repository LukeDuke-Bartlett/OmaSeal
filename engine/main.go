package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

const appName = "omaseal"

// logOpResult records a telemetry line when a store-facing operation fails —
// errors, keyring timeouts, and gate denials. Successes already leave stats
// lines; failures previously left no trace at all, which made wedged daemon
// hangs invisible until processes accumulated. `omaseal stats` aggregates
// these lines into the failure counters.
func logOpResult(op, target string, start time.Time, err error) {
	if err == nil {
		return
	}
	result := "error"
	if errors.Is(err, errKeyringTimeout) {
		result = "timeout"
	}
	WriteLog("op=%s target=\"%s\" dur=%dms result=%s code=%s", op, target,
		time.Since(start).Milliseconds(), result, codeFromError(err))
}

func usage() {
	fmt.Fprint(os.Stderr, `omaseal — system keyring for Omarchy

Usage:
  omaseal set <service> <account>          store secret from stdin
  omaseal get <service> <account>          print stored secret
  omaseal reveal <service> <account>       print secret after user-presence gate
  omaseal del <service> <account>          delete stored secret
  omaseal list [service] [--json] [--sort=used|recent|name]
                                           list stored secrets (optionally sorted)
  omaseal stats [--json]                   display access analytics & usage leaderboard
  omaseal manifest [show|init|check|path|audit|apply <file>]  AI agent access policy
  omaseal jev [status|enable|disable]      optional Jev decision layer (off by default)
  omaseal resolve <service> <account>      resolve + cache from keyring/op/bw/prompt
  omaseal run -e NAME=svc/acct -- <cmd>    launch a command with secrets injected into its env
  omaseal sudo [-r svc/acct] -- <cmd>      feed your sudo password after a presence check
  omaseal import 1password [vault]         import all 1Password items
  omaseal import bitwarden                 import all Bitwarden items
  omaseal migrate [--dry-run] [-y]         copy every Secret Service item into the native store
  omaseal mcp                              start MCP stdio server
  omaseal mcp install <agent> [--dir .]    write mcp config for one agent
  omaseal mcp install-detected             wire every detected + assigned agent
  omaseal mcp install-all                  write mcp config for every known agent
  omaseal mcp status [--json]              show detected/installed agent configs
  omaseal ipc <method> <json-args>         JSON IPC for other plugins
  omaseal ping                             health check (json with --json)
  omaseal selftest                         keyring round-trip test
  omaseal doctor                           check the environment and dependencies
  omaseal logs [n]                         show recent non-secret log lines
  omaseal logs verify [--anchor <file>]    check the log's hash chain for tampering
  omaseal logs seal <file>                 anchor the current chain head to a file
  omaseal setup [--yes]                    onboarding: doctor + agent wiring
  omaseal agent mode <open|ask|lock> [min] [--ungated] set agent/MCP trust mode
  omaseal agent unlock                     user-presence unlock for ask mode
      --passphrase-stdin                   native backend: read the store passphrase
                                           from stdin (panels, launchers) — the
                                           passphrase itself is the presence proof
  omaseal agent lock                       revoke agent session
  omaseal agent status [--json]            show agent policy and session
  omaseal agent keepalive [on|off]         session renews on activity (ask mode)
  omaseal agent primary <name>             set your main agent
  omaseal agent defaults [names...|--clear] set assigned default agents

References:
  Everywhere <service> <account> is accepted, a single omaseal://<service>/<account>
  reference works too; the account may contain '/' (e.g. omaseal://browseros/
  openrouter-work/apiKey). 'omaseal list' accepts omaseal://<service>[/].

Examples:
  omaseal set openrouter default < secret.txt
  omaseal get openrouter default
  omaseal get omaseal://openrouter/default
  omaseal reveal openrouter default
  omaseal del openrouter default
  omaseal list --sort=used
  omaseal list omaseal://browseros/
  omaseal stats
  omaseal manifest
  omaseal manifest check openrouter default
  omaseal resolve openrouter default
  omaseal resolve omaseal://browseros/openrouter-work/apiKey
  omaseal import 1password pace-dev
  omaseal ipc ping '{}'
  omaseal ipc get '{"service":"openrouter","account":"default"}'
`)
}

func main() {
	SetLogOutput()

	if err := selectStore(); err != nil {
		fmt.Fprintln(os.Stderr, "omaseal:", err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	WriteLog("omaseal %s: command %s", version, cmd)

	switch cmd {
	case "version", "--version", "-v":
		printVersion()
		return
	case "set":
		handleSet()
	case "get":
		handleGet()
	case "reveal":
		handleReveal()
	case "del", "delete":
		handleDel()
	case "list":
		handleList()
	case "stats", "analytics":
		handleStats()
	case "manifest", "robots":
		handleManifest()
	case "resolve":
		handleResolve()
	case "run":
		handleRun()
	case "sudo":
		handleSudo()
	case "clipclear":
		handleClipclear()
	case "import":
		handleImport()
	case "mcp":
		if len(os.Args) >= 3 && os.Args[2] == "install" {
			handleMCPInstall()
		} else if len(os.Args) >= 3 && os.Args[2] == "install-all" {
			handleMCPInstallAll()
		} else if len(os.Args) >= 3 && os.Args[2] == "install-detected" {
			handleMCPInstallDetected()
		} else if len(os.Args) >= 3 && os.Args[2] == "status" {
			handleMCPStatus()
		} else {
			runMCP()
		}
	case "ipc":
		handleIPC()
	case "ping":
		handlePing()
	case "selftest":
		handleSelfTest()
	case "doctor":
		handleDoctor()
	case "keyring":
		runKeyring(os.Args[2:])
	case "migrate":
		handleMigrate(os.Args[2:])
	case "logs":
		handleLogs()
	case "setup":
		runSetup()
	case "agent":
		handleAgent()
	case "jev":
		handleJev()
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
}

func handleSet() {
	service, account, err := argCredentials(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(1)
	}
	secret, err := readSecret()
	if err != nil {
		printError("reading secret: ", err)
		os.Exit(1)
	}
	if secret == "" {
		fmt.Fprintln(os.Stderr, "error: secret cannot be empty")
		os.Exit(1)
	}
	start := time.Now()
	err = Set(service, account, secret)
	logOpResult("set", service+"/"+account, start, err)
	if err != nil {
		printError("storing secret: ", err)
		os.Exit(1)
	}
	WriteLog("set %s/%s", service, account)
	fmt.Println("ok")
}

func handleGet() {
	service, account, err := argCredentialsLoose(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(1)
	}
	start := time.Now()
	secret, err := Get(service, account)
	logOpResult("get", service+"/"+account, start, err)
	if err != nil {
		printError("retrieving secret: ", err)
		os.Exit(1)
	}
	WriteLog("get %s/%s", service, account)
	fmt.Print(secret)
}

func handleDel() {
	service, account, err := argCredentialsLoose(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(1)
	}
	start := time.Now()
	err = Delete(service, account)
	logOpResult("del", service+"/"+account, start, err)
	if err != nil {
		printError("deleting secret: ", err)
		os.Exit(1)
	}
	WriteLog("del %s/%s", service, account)
	fmt.Println("ok")
}

func handleList() {
	jsonOut := hasFlag(os.Args, "--json")

	var positionals []string
	sortMode := ""
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "--json":
		case arg == "--hits":
			sortMode = "used"
		case strings.HasPrefix(arg, "--sort=") || strings.HasPrefix(arg, "--sort-by="):
			sortMode = arg[strings.Index(arg, "=")+1:]
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintln(os.Stderr, "error: unknown flag:", arg)
			os.Exit(1)
		default:
			positionals = append(positionals, arg)
		}
	}
	service, err := argService(positionals)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	start := time.Now()
	items, err := listWithUsage(service, sortMode)
	logOpResult("list", service, start, err)
	if err != nil {
		printError("listing secrets: ", err)
		os.Exit(1)
	}
	WriteLog("list: %d secrets", len(items))

	if jsonOut {
		b, _ := json.Marshal(items)
		fmt.Println(string(b))
		return
	}

	if len(items) == 0 {
		fmt.Println("No secrets stored.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if sortMode == "used" || sortMode == "hits" || sortMode == "recent" {
		fmt.Fprintln(w, "SERVICE\tACCOUNT\tHITS\tLAST ACCESSED\tLABEL")
		for _, it := range items {
			last := "-"
			if it.LastAccessed != nil {
				last = it.LastAccessed.Format("2006-01-02 15:04:05")
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", sanitizeField(it.Service), sanitizeField(it.Account), it.AccessCount, last, sanitizeField(it.Label))
		}
	} else {
		fmt.Fprintln(w, "SERVICE\tACCOUNT\tLABEL")
		for _, it := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\n", sanitizeField(it.Service), sanitizeField(it.Account), sanitizeField(it.Label))
		}
	}
	w.Flush()
}

func handleReveal() {
	service, account, err := argCredentialsLoose(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(1)
	}
	start := time.Now()
	if err := requireUserPresence(context.Background(), fmt.Sprintf("reveal %s/%s", service, account), loadAgentPolicyOrDefault()); err != nil {
		logOpResult("reveal", service+"/"+account, start, err)
		printError("user-presence gate: ", err)
		os.Exit(1)
	}
	secret, err := Get(service, account)
	logOpResult("reveal", service+"/"+account, start, err)
	if err != nil {
		printError("getting secret: ", err)
		os.Exit(1)
	}
	WriteLog("reveal %s/%s", service, account)
	fmt.Print(secret)
}

func handleIPC() {
	if len(os.Args) != 4 {
		usage()
		os.Exit(1)
	}
	method := os.Args[2]
	jsonArgs := os.Args[3]
	WriteLog("ipc %s", method)
	runIPC(method, jsonArgs)
}

func handleResolve() {
	service, account, err := argCredentialsLoose(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(1)
	}
	start := time.Now()
	secret, err := Resolve(context.Background(), service, account, true, true)
	logOpResult("resolve", service+"/"+account, start, err)
	if err != nil {
		printError("resolving secret: ", err)
		os.Exit(1)
	}
	WriteLog("resolve %s/%s", service, account)
	fmt.Print(secret)
}

func handleImport() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}
	source := os.Args[2]
	var err error
	ctx := context.Background()
	switch source {
	case "1password", "op":
		vault := ""
		if len(os.Args) >= 4 {
			vault = os.Args[3]
		}
		err = ImportOnePassword(ctx, vault)
	case "bitwarden", "bw":
		err = ImportBitwarden(ctx)
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		printError("importing: ", err)
		os.Exit(1)
	}
	WriteLog("import %s", source)
	fmt.Println("ok")
}

func handleLogs() {
	if len(os.Args) >= 3 {
		switch os.Args[2] {
		case "verify":
			handleLogsVerify()
			return
		case "seal":
			handleLogsSeal()
			return
		}
	}
	n := 50
	jsonOut := false
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--json" {
			jsonOut = true
			continue
		}
		if v, err := strconv.Atoi(os.Args[i]); err == nil && v > 0 {
			n = v
		}
	}
	if jsonOut {
		lines, err := ReadLogJSON(n)
		if err != nil {
			printError("reading log: ", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(lines)
		fmt.Println(string(b))
		return
	}
	lines, err := ReadLog(n)
	if err != nil {
		printError("reading log: ", err)
		os.Exit(1)
	}
	for _, l := range lines {
		fmt.Println(l)
	}
}

// handleLogsVerify checks the log's hash chain: pairwise consistency, a
// sidecar head match, and — with --anchor — that every sealed head still
// appears in the surviving chain. Exit 1 means tampering evidence.
func handleLogsVerify() {
	anchor := ""
	jsonOut := false
	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--json":
			jsonOut = true
		case "--anchor":
			if i+1 < len(os.Args) {
				anchor = os.Args[i+1]
				i++
			}
		}
	}
	logPath := LogPath()
	rep, err := verifyLogChain(logPath, chainStatePath(logPath), anchor)
	if err != nil {
		printError("verifying log chain: ", err)
		os.Exit(1)
	}
	if jsonOut {
		b, _ := json.Marshal(rep)
		fmt.Println(string(b))
	} else {
		printChainReport(rep, anchor)
	}
	if rep.Tampered() {
		os.Exit(1)
	}
}

// handleLogsSeal appends the current chain head to a user-chosen anchor
// file. Anchored heads that later disappear from the chain prove the log
// was rewritten — the same-uid recompute escape closed by keeping the
// anchor outside the state dir (a synced repo, another machine).
func handleLogsSeal() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: omaseal logs seal <anchor-file>")
		os.Exit(2)
	}
	logPath := LogPath()
	unlock := sharedLogLock(logPath)
	head := resumeChainHead(logPath)
	unlock()
	if head == chainGenesis {
		printError("sealing log chain: ", fmt.Errorf("no chained lines yet — the log is empty or predates chaining"))
		os.Exit(1)
	}
	if err := sealHead(os.Args[3], head); err != nil {
		printError("sealing log chain: ", err)
		os.Exit(1)
	}
	fmt.Printf("sealed %s → %s\n", head[:16], os.Args[3])
}

// chainStatePath locates the sidecar head next to the log file.
func chainStatePath(logPath string) string {
	return filepath.Join(filepath.Dir(logPath), "omaseal.chain")
}

func printChainReport(rep *chainReport, anchor string) {
	if rep.LinesChecked == 0 {
		fmt.Println("log chain: empty — no lines checked")
		return
	}
	if rep.ChainedLines == 0 {
		fmt.Printf("log chain: %d lines, none chained yet (pre-chain history only)\n", rep.LinesChecked)
		return
	}
	status := "verified"
	if rep.StartsMidChain {
		status = "verified (starts mid-chain — log truncated at some point)"
	}
	fmt.Printf("log chain: %s — %d/%d lines chained, head %s\n",
		status, rep.ChainedLines, rep.LinesChecked, rep.Head[:16])
	if rep.DivergenceLine != 0 {
		fmt.Printf("  TAMPER: line %d — %s\n", rep.DivergenceLine, rep.DivergenceReason)
	}
	if rep.SidecarMismatch {
		fmt.Println("  TAMPER: sidecar head disagrees with the log tail")
	}
	for head, ok := range rep.Anchors {
		if ok {
			fmt.Printf("  anchor %.16s: present in chain\n", head)
		} else {
			fmt.Printf("  TAMPER: anchored head %.16s is absent — history rewritten since that seal\n", head)
		}
	}
	if anchor != "" && len(rep.Anchors) == 0 {
		fmt.Printf("  note: %s has no usable anchor entries\n", anchor)
	}
}

// selftestRoundTrip runs a set/get/delete round-trip against the live keyring.
// The probe uses a fixed name and is removed before writing, so a key left
// behind by a timed-out or killed run is cleaned up on the next run.
func selftestRoundTrip() error {
	service := "omaseal-selftest"
	account := "selftest"
	secret := fmt.Sprintf("omaseal-selftest-%d", time.Now().UnixNano())

	_ = Delete(service, account) // clear any orphan from a previous timed-out run
	if err := Set(service, account, secret); err != nil {
		return fmt.Errorf("set: %w", err)
	}
	got, err := Get(service, account)
	if err != nil {
		_ = Delete(service, account)
		return fmt.Errorf("get: %w", err)
	}
	if got != secret {
		_ = Delete(service, account)
		return fmt.Errorf("compare: round-trip mismatch")
	}
	if err := Delete(service, account); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	// Only a not-found error proves the delete took effect; any other error
	// (keyring outage, permission) would falsely pass the verification.
	if _, err := Get(service, account); err == nil {
		return fmt.Errorf("verify-delete: secret still readable after delete")
	} else if codeFromError(err) != "not_found" {
		return fmt.Errorf("verify-delete: %w", err)
	}
	WriteLog("selftest passed")
	return nil
}

// handleSelfTest runs a set/get/delete round-trip against the live keyring.
// Agents and users can call it to verify the whole stack end to end.
func handleSelfTest() {
	if err := selftestRoundTrip(); err != nil {
		printError("selftest ", err)
		os.Exit(1)
	}
	fmt.Println("selftest ok: set/get/delete round-trip passed")
}

// readSecretDeadline reads stdin like readSecret but gives up after d, so
// callers that cannot see their caller's stdin (IPC) fail instead of hanging
// on a held-open pipe.
func readSecretDeadline(d time.Duration) (string, error) {
	return readSecretFrom(os.Stdin, d)
}

// readSecretFrom is readSecretDeadline on an injected reader so IPC tests
// can drive the piped-secret path without a real stdin.
func readSecretFrom(r io.Reader, d time.Duration) (string, error) {
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// Cap the read — a same-uid caller piping an endless stream should
		// hit a bound, not grow memory for the full deadline. Over-cap is an
		// error, not silent truncation — a truncated secret is worse than none.
		const maxSecret = 1 << 20
		b, err := io.ReadAll(io.LimitReader(r, maxSecret+1))
		if err == nil && len(b) > maxSecret {
			err = fmt.Errorf("secret exceeds %d bytes", maxSecret)
		}
		ch <- result{strings.TrimSuffix(string(b), "\n"), err}
	}()
	select {
	case r := <-ch:
		return r.s, r.err
	case <-time.After(d):
		return "", fmt.Errorf("timed out waiting for the secret on stdin")
	}
}

// readSecret reads a secret from stdin without a trailing newline.
func readSecret() (string, error) {
	if !isStdinTTY() {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return strings.TrimSuffix(string(b), "\n"), nil
	}

	fmt.Fprint(os.Stderr, "Enter secret: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // ReadPassword does not echo the newline
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func isStdinTTY() bool {
	return isTerminal(os.Stdin)
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

func hasFlag(args []string, name string) bool {
	for _, a := range args[1:] {
		if a == name {
			return true
		}
	}
	return false
}

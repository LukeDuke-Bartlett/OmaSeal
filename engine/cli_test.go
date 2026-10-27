package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// captureLegacy runs args through the real command tree with the legacy
// dispatcher stubbed, and returns the argv the old handlers would have seen.
func captureLegacy(t *testing.T, args ...string) (argv []string, called bool, err error) {
	t.Helper()
	old := legacyRun
	legacyRun = func(a []string) { argv, called = a, true }
	t.Cleanup(func() { legacyRun = old })

	root := newRootCmd()
	root.SilenceErrors, root.SilenceUsage = true, true
	root.SetOut(&strings.Builder{})
	root.SetErr(&strings.Builder{})
	root.SetArgs(args)
	err = root.Execute()
	return argv, called, err
}

// The central compatibility promise: every invocation that worked before the
// revamp — and every new spelling — reaches the unchanged legacy handler with
// the argv that handler has always parsed.
func TestCommandTreeTranslatesToLegacyArgv(t *testing.T) {
	cases := []struct {
		in   string
		want string // legacy argv, space-joined
	}{
		// secrets: old names and new names
		{"set openrouter default", "set openrouter default"},
		{"set --ask openrouter default", "ask-save openrouter default"},
		{"ask-save openrouter default", "ask-save openrouter default"},
		{"get openrouter default", "get openrouter default"},
		{"get omaseal://openrouter/default", "get omaseal://openrouter/default"},
		{"get --reveal openrouter default", "reveal openrouter default"},
		{"get openrouter default --reveal", "reveal openrouter default"},
		{"reveal openrouter default", "reveal openrouter default"},
		{"get --resolve openrouter default", "resolve openrouter default"},
		{"resolve openrouter default", "resolve openrouter default"},
		{"rm a b", "del a b"},
		{"del a b", "del a b"},
		{"delete a b", "del a b"},
		{"ls", "list"},
		{"ls --json", "list --json"},
		{"ls --sort=used openrouter", "list --sort=used openrouter"},
		{"list --json", "list --json"},
		{"list openrouter --hits", "list openrouter --hits"},
		{"run -e K=svc/acct -- cmd --version", "run -e K=svc/acct -- cmd --version"},
		{"sudo -r svc/acct -- ls -h", "sudo -r svc/acct -- ls -h"},
		{"clipclear a b", "clipclear a b"},

		// agents
		{"agent mode ask 30 --ungated", "agent mode ask 30 --ungated"},
		{"agent unlock --passphrase-stdin", "agent unlock --passphrase-stdin"},
		{"agent lock", "agent lock"},
		{"agent status --json", "agent status --json"},
		{"agent keepalive on", "agent keepalive on"},
		{"agent keep-alive off", "agent keep-alive off"}, // typed spelling is kept so the audit line is identical,
		{"agent primary hermes", "agent primary hermes"},
		{"agent defaults --clear", "agent defaults --clear"},
		{"mcp", "mcp"},
		{"mcp serve", "mcp"},
		{"mcp status --json", "mcp status --json"},
		{"mcp install hermes", "mcp install hermes"},
		{"mcp install claude --dir .", "mcp install claude --dir ."},
		{"mcp install --detected", "mcp install-detected"},
		{"mcp install --detected --dir /x", "mcp install-detected --dir /x"},
		{"mcp install --all", "mcp install-all"},
		{"mcp install-all", "mcp install-all"},
		{"mcp install-detected", "mcp install-detected"},
		{"policy", "manifest"},
		{"policy show", "manifest show"},
		{"policy audit --json", "manifest audit --json"},
		{"policy apply f.json --yes", "manifest apply f.json --yes"},
		{"manifest", "manifest"},
		{"manifest check openrouter default", "manifest check openrouter default"},
		{"robots show", "manifest show"},

		// health
		{"doctor", "doctor"},
		{"doctor --json", "doctor --json"},
		{"doctor setup --yes", "setup --yes"},
		{"doctor selftest", "selftest"},
		{"doctor ping --json", "ping --json"},
		{"setup --yes", "setup --yes"},
		{"selftest", "selftest"},
		{"ping --json", "ping --json"},
		{"stats --json", "stats --json"},
		{"analytics", "stats"},
		{"logs", "logs"},
		{"logs 25 --json", "logs 25 --json"},
		{"logs verify --anchor f", "logs verify --anchor f"},
		{"logs seal f", "logs seal f"},

		// setup
		{"import 1password pace-dev", "import 1password pace-dev"},
		{"import op pace-dev", "import op pace-dev"},
		{"import bitwarden", "import bitwarden"},
		{"import bw", "import bw"},
		{"import secretservice --dry-run -y", "migrate --dry-run -y"},
		{"migrate --dry-run", "migrate --dry-run"},
		{"keyring", "keyring"},
		{"keyring status", "keyring status"},
		{"keyring migrate --dry-run --delete-old", "keyring migrate --dry-run --delete-old"},
		{"provider serve", "provider serve"},
		{"provider status --json", "provider status --json"},
		{"provider enable", "provider enable"},
		{"provider disable", "provider disable"},

		// plumbing that other plugins call
		{`ipc get {"service":"a","account":"b"}`, `ipc get {"service":"a","account":"b"}`},
		{"jev status", "jev status"},
		{"version", "version"},
	}
	for _, c := range cases {
		args := strings.Fields(c.in) // no case carries a space inside one argument
		argv, called, err := captureLegacy(t, args...)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if !called {
			t.Errorf("%q: legacy handler not reached", c.in)
			continue
		}
		if got := strings.Join(argv, " "); got != c.want {
			t.Errorf("%q: legacy argv = %q, want %q", c.in, got, c.want)
		}
	}
}

// Every verb the pre-revamp CLI accepted must still resolve — as a visible
// command or a hidden alias — and none may fall through to the root.
func TestEveryPreRevampVerbStillResolves(t *testing.T) {
	legacyVerbs := []string{
		"version", "set", "ask-save", "get", "reveal", "del", "delete", "list",
		"stats", "analytics", "manifest", "robots", "resolve", "run", "sudo",
		"clipclear", "import", "mcp", "ipc", "ping", "selftest", "doctor",
		"keyring", "migrate", "logs", "setup", "agent", "jev", "provider",
	}
	root := newRootCmd()
	for _, v := range legacyVerbs {
		cmd, _, err := root.Find([]string{v})
		if err != nil || cmd == root {
			t.Errorf("legacy verb %q no longer resolves (err=%v)", v, err)
		}
	}
	for _, sub := range [][]string{
		{"mcp", "install"}, {"mcp", "install-all"}, {"mcp", "install-detected"}, {"mcp", "status"},
		{"logs", "verify"}, {"logs", "seal"}, {"keyring", "migrate"}, {"keyring", "status"},
		{"agent", "mode"}, {"agent", "unlock"}, {"agent", "lock"}, {"agent", "status"},
		{"agent", "keepalive"}, {"agent", "keep-alive"}, {"agent", "primary"}, {"agent", "defaults"},
		{"manifest", "show"}, {"manifest", "init"}, {"manifest", "check"}, {"manifest", "path"},
		{"manifest", "audit"}, {"manifest", "apply"}, {"import", "1password"}, {"import", "op"},
		{"import", "bitwarden"}, {"import", "bw"},
	} {
		cmd, _, err := root.Find(sub)
		last := sub[len(sub)-1]
		if err != nil || cmd == nil || !(cmd.Name() == last || cmd.HasAlias(last)) {
			t.Errorf("legacy subcommand %v no longer resolves to its own command (err=%v)", sub, err)
		}
	}
}

// The old names are aliases, not part of the advertised tree.
func TestPreRevampNamesAreHidden(t *testing.T) {
	root := newRootCmd()
	visible := map[string]bool{}
	for _, c := range root.Commands() {
		if !c.Hidden {
			visible[c.Name()] = true
			for _, a := range c.Aliases {
				visible[a] = true
			}
		}
	}
	// Names that exist only as aliases or hidden commands: none may be a
	// visible top-level entry.
	for _, old := range []string{"reveal", "resolve", "ask-save", "del", "delete", "list",
		"analytics", "manifest", "robots", "ping", "selftest", "setup", "migrate", "ipc", "jev", "clipclear", "version"} {
		for _, c := range root.Commands() {
			if c.Name() == old && !c.Hidden {
				t.Errorf("%q is a visible top-level command; it should be a hidden alias", old)
			}
		}
	}
	// Roughly eight groups of everyday commands, not twenty-odd verbs.
	// Rotation flags (flag/unflag) added two verbs after the revamp.
	var top int
	for _, c := range root.Commands() {
		if !c.Hidden && c.GroupID != "" {
			top++
		}
	}
	if top > 18 {
		t.Errorf("%d visible top-level commands; the revamp promised a smaller surface", top)
	}
}

func TestHelpFlagDoesNotReachLegacyHandler(t *testing.T) {
	for _, args := range [][]string{{"get", "--help"}, {"rm", "-h"}, {"set", "--help"}, {"run", "--help"}} {
		_, called, err := captureLegacy(t, args...)
		if err != nil {
			t.Errorf("%v: %v", args, err)
		}
		if called {
			t.Errorf("%v: --help ran the command instead of showing help", args)
		}
	}
}

func TestMistypedServingGroupSubcommandIsAnError(t *testing.T) {
	// Bare `mcp` serves; a typo must not silently start a server on stdin.
	for _, args := range [][]string{{"mcp", "instal", "claude"}, {"policy", "bogus"}, {"keyring", "oops"}, {"agent", "bogus"}, {"provider", "bogus"}, {"import", "nope"}} {
		_, called, err := captureLegacy(t, args...)
		if err == nil || called {
			t.Errorf("%v: want an unknown-command error and no handler call (err=%v called=%v)", args, err, called)
		}
	}
}

func TestConflictingFoldFlags(t *testing.T) {
	for _, args := range [][]string{{"get", "--reveal", "--resolve", "a", "b"}, {"mcp", "install", "--all", "--detected"}} {
		_, called, err := captureLegacy(t, args...)
		if err == nil || called {
			t.Errorf("%v: want an error (err=%v called=%v)", args, err, called)
		}
	}
}

func TestUnknownRootCommandIsAnError(t *testing.T) {
	_, called, err := captureLegacy(t, "definitely-not-a-command")
	if err == nil || called {
		t.Fatalf("unknown command must error without a handler call (err=%v called=%v)", err, called)
	}
}

func TestTakeFlagStopsAtDoubleDash(t *testing.T) {
	// A flag-looking word after `--` belongs to the wrapped command.
	rest, found := takeFlag([]string{"-e", "K=a/b", "--", "tool", "--reveal"}, "--reveal")
	if found || !reflect.DeepEqual(rest, []string{"-e", "K=a/b", "--", "tool", "--reveal"}) {
		t.Fatalf("takeFlag consumed a flag after --: found=%v rest=%v", found, rest)
	}
}

func TestEverySpecParentIsDeclaredFirst(t *testing.T) {
	// newRootCmd panics on an orphan; make that a test failure, not a crash.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("command tree is malformed: %v", r)
		}
	}()
	root := newRootCmd()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Short == "" && c != root {
			t.Errorf("command %q has no short description", c.CommandPath())
		}
		for _, sc := range c.Commands() {
			walk(sc)
		}
	}
	walk(root)
}

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/duketopceo/OmaSeal/engine/ui"
	"github.com/spf13/cobra"
)

// The command tree.
//
// Every command here is a thin front for a legacy handler: the handlers keep
// reading os.Args exactly as they always did, so argument parsing, output,
// exit codes, user-presence gating and audit logging are the code that already
// shipped. This layer only owns naming, grouping, help and aliases.
//
// Cobra flag parsing is switched off on every leaf (DisableFlagParsing), so a
// secret-bearing or plugin-parsed argv reaches the handler untouched. Flags
// are declared only so they show up in `--help`.

// Group IDs for the top-level help.
const (
	groupSecrets = "secrets"
	groupAgents  = "agents"
	groupHealth  = "health"
	groupSetup   = "setup"
)

// legacyRun hands an argv (without the program name) to the pre-cobra
// dispatcher. A variable so tests can capture the translation.
var legacyRun = runLegacy

// activeCmd is the command being executed, for usage() on argument errors.
var activeCmd *cobra.Command

// cmdSpec describes one command in the tree.
type cmdSpec struct {
	path    string // space-separated, e.g. "agent mode"
	use     string // argument synopsis, e.g. "<service> <account>"
	short   string
	long    string
	example string
	group   string // top-level help group (top-level commands only)
	aliases []string
	hidden  bool
	flags   []string // "name|description" documented flags
	// legacy is the argv prefix handed to the legacy dispatcher; the
	// command's own arguments are appended.
	legacy []string
	// rewrite, when set, maps the command's arguments to the full legacy argv.
	rewrite func(args []string) ([]string, error)
	// serve marks a group whose bare invocation runs its legacy handler.
	serve bool
	// loose lets a serving group take positional words that are not
	// subcommands (`logs 25`).
	loose bool
}

// cliSpecs is the whole surface, visible commands first, then the hidden
// legacy names kept for one release.
var cliSpecs = []cmdSpec{
	// ── Secrets ─────────────────────────────────────────────────────────────
	{path: "set", use: "<service> <account>", group: groupSecrets,
		short:   "Store a secret read from stdin",
		long:    "Store a secret read from stdin (hidden prompt on a terminal).\n\nWith --ask, pop up a dialog for the value instead — meant for agents: the value never passes through the caller.",
		example: "  omaseal set openrouter default < key.txt\n  omaseal set --ask openrouter default",
		flags:   []string{"ask|prompt in a dialog instead of reading stdin"},
		rewrite: func(args []string) ([]string, error) {
			rest, found := takeFlag(args, "--ask")
			if found {
				return append([]string{"ask-save"}, rest...), nil
			}
			return append([]string{"set"}, args...), nil
		}},
	{path: "get", use: "<service> <account>", group: groupSecrets,
		short:   "Print a stored secret",
		long:    "Print a stored secret, raw, to stdout (never decorated, safe to pipe).\n\n--reveal asks for user presence first; --resolve also consults 1Password/Bitwarden and caches the result.",
		example: "  omaseal get openrouter default\n  omaseal get omaseal://openrouter/default\n  omaseal get --reveal openrouter default",
		flags:   []string{"reveal|require a user-presence confirmation first", "resolve|look in keyring, 1Password, Bitwarden or prompt, and cache"},
		rewrite: rewriteGet},
	{path: "ls", use: "[service]", group: groupSecrets, aliases: []string{"list"},
		short:   "List stored secrets",
		example: "  omaseal ls\n  omaseal ls --sort=used\n  omaseal ls omaseal://browseros/\n  omaseal ls --json",
		flags:   []string{"json|machine-readable output", "sort=|used, recent or name"},
		legacy:  []string{"list"}},
	{path: "rm", use: "<service> <account>", group: groupSecrets, aliases: []string{"del", "delete"},
		short:  "Delete a stored secret",
		legacy: []string{"del"}},
	{path: "run", use: "-- <command>", group: groupSecrets,
		short:   "Run a command with secrets injected into its environment",
		long:    "Run a command with secrets injected into its environment. Nothing touches disk and the value never appears in argv.\n\n  omaseal run -e NAME=<service>/<account> [-e ...] [--resolve] -- <command> [args...]",
		example: "  omaseal run -e OPENROUTER_API_KEY=openrouter/default -- hermes",
		flags:   []string{"e=|NAME=service/account binding (repeatable)"},
		legacy:  []string{"run"}},
	{path: "sudo", use: "-- <command>", group: groupSecrets,
		short:  "Run sudo, feeding your password after a presence check",
		long:   "Run sudo, feeding your password after a presence check.\n\n  omaseal sudo [-r <service>/<account>] -- <command> [args...]",
		legacy: []string{"sudo"}},
	{path: "flag", use: "<service> <account> [reason]", group: groupSecrets,
		short:   "Mark a secret for rotation (leaked, stale)",
		long:    "Mark a stored secret as needing rotation — e.g. an agent saw the value leak into a log or transcript. Reads still work but every surface warns until a new value is stored.",
		example: "  omaseal flag openrouter default key printed into transcript\n  omaseal flag omaseal://openrouter/default",
		legacy:  []string{"flag"}},
	{path: "unflag", use: "<service> <account>", group: groupSecrets,
		short:  "Clear a rotation flag without storing a new value",
		legacy: []string{"unflag"}},

	// ── Agents ──────────────────────────────────────────────────────────────
	{path: "agent", group: groupAgents,
		short: "Control how AI agents may reach your secrets (open, ask, lock)"},
	{path: "agent mode", use: "<open|ask|lock> [minutes]",
		short:   "Set the agent trust mode",
		long:    "Set the agent trust mode. Loosening it asks for user presence (fingerprint or a dialog) first and gives up with a clear message after a minute if nobody answers.",
		example: "  omaseal agent mode ask 30\n  omaseal agent mode lock",
		flags:   []string{"ungated|with ask: skip presence when no mechanism exists (deliberate opt-out)"},
		legacy:  []string{"agent", "mode"}},
	{path: "agent unlock", short: "Unlock an agent session (ask mode)",
		flags:  []string{"passphrase-stdin|native backend: read the store passphrase from stdin"},
		legacy: []string{"agent", "unlock"}},
	{path: "agent lock", short: "Revoke the agent session", legacy: []string{"agent", "lock"}},
	{path: "agent status", short: "Show agent policy and session",
		flags: []string{"json|machine-readable output"}, legacy: []string{"agent", "status"}},
	{path: "agent keepalive", use: "[on|off]", aliases: []string{"keep-alive"},
		short: "Renew the session on activity (ask mode)", legacy: []string{"agent", "keepalive"}},
	{path: "agent primary", use: "<name>", short: "Set your main agent", legacy: []string{"agent", "primary"}},
	{path: "agent defaults", use: "[names... | --clear]", short: "Show or set the assigned default agents",
		legacy: []string{"agent", "defaults"}},

	{path: "mcp", group: groupAgents, serve: true,
		short:  "The MCP server and agent wiring",
		long:   "The MCP server and agent wiring.\n\nBare `omaseal mcp` starts the stdio server (what agents launch); `omaseal mcp serve` is the explicit spelling.",
		legacy: []string{"mcp"}},
	{path: "mcp serve", short: "Start the MCP stdio server", legacy: []string{"mcp"}},
	{path: "mcp install", use: "<agent>",
		short:   "Write the OmaSeal MCP entry into an agent's config",
		long:    "Write the OmaSeal MCP entry into an agent's config.\n\n<agent> wires one agent; --detected wires every agent found here plus your defaults; --all wires every known agent.",
		example: "  omaseal mcp install hermes\n  omaseal mcp install --detected",
		flags:   []string{"detected|every detected agent plus your defaults and primary", "all|every known agent", "dir=|write the project-level config in this directory"},
		rewrite: rewriteMCPInstall},
	{path: "mcp status", short: "Show detected and installed agent configs",
		flags: []string{"json|machine-readable output"}, legacy: []string{"mcp", "status"}},

	{path: "policy", group: groupAgents, serve: true, aliases: []string{"manifest", "robots"},
		short:  "The agent access policy (which agents may read which secrets)",
		legacy: []string{"manifest"}},
	{path: "policy show", short: "Show the policy", legacy: []string{"manifest", "show"}},
	{path: "policy init", short: "Create a starter policy", legacy: []string{"manifest", "init"}},
	{path: "policy check", use: "<service> <account>", short: "Check what the policy says about one secret",
		legacy: []string{"manifest", "check"}},
	{path: "policy path", short: "Print the policy file path", legacy: []string{"manifest", "path"}},
	{path: "policy audit", short: "Audit recent access against the policy",
		flags: []string{"json|machine-readable output"}, legacy: []string{"manifest", "audit"}},
	{path: "policy apply", use: "<file>", short: "Apply a reviewed policy change",
		flags: []string{"yes|apply non-expanding changes without asking"}, legacy: []string{"manifest", "apply"}},

	// ── Health ──────────────────────────────────────────────────────────────
	{path: "doctor", group: groupHealth, serve: true, loose: true,
		short: "Check the environment (and run setup, selftest or ping)",
		long:  "Check the environment and dependencies.\n\n  doctor setup      guided onboarding: checks, then agent wiring\n  doctor selftest   keyring round-trip test\n  doctor ping       health check as JSON",
		flags: []string{"json|machine-readable output"}, legacy: []string{"doctor"}},
	{path: "doctor setup", short: "Guided onboarding: doctor + agent wiring",
		flags: []string{"yes|wire every detected agent without asking"}, legacy: []string{"setup"}},
	{path: "doctor selftest", short: "Keyring round-trip test", legacy: []string{"selftest"}},
	{path: "doctor ping", short: "Health check (JSON with --json)", flags: []string{"json|machine-readable output"},
		legacy: []string{"ping"}},
	{path: "stats", group: groupHealth, aliases: []string{"analytics"},
		short: "Access analytics and usage leaderboard",
		flags: []string{"json|machine-readable output"}, legacy: []string{"stats"}},
	{path: "logs", use: "[n]", group: groupHealth, serve: true, loose: true,
		short: "Show recent non-secret log lines",
		flags: []string{"json|machine-readable output"}, legacy: []string{"logs"}},
	{path: "logs verify", short: "Check the log's hash chain for tampering",
		flags: []string{"anchor=|file of sealed heads to check", "json|machine-readable output"}, legacy: []string{"logs", "verify"}},
	{path: "logs seal", use: "<file>", short: "Anchor the current chain head to a file", legacy: []string{"logs", "seal"}},

	// ── Setup ───────────────────────────────────────────────────────────────
	{path: "import", group: groupSetup, short: "Bring secrets in from another store"},
	{path: "import 1password", use: "[vault]", aliases: []string{"op"}, short: "Import all 1Password items",
		legacy: []string{"import", "1password"}},
	{path: "import bitwarden", aliases: []string{"bw"}, short: "Import all Bitwarden items",
		legacy: []string{"import", "bitwarden"}},
	{path: "import secretservice", short: "Copy every Secret Service item into the native store",
		flags:  []string{"dry-run|show the plan only", "yes|skip the confirmation"},
		legacy: []string{"migrate"}},
	{path: "keyring", group: groupSetup, serve: true, short: "Inspect or password-protect the system keyring",
		legacy: []string{"keyring"}},
	{path: "keyring status", short: "Show the keyring state", legacy: []string{"keyring", "status"}},
	{path: "keyring migrate", short: "Move secrets into a password-protected keyring",
		flags:  []string{"dry-run|show the plan only", "delete-old|remove the old collection after verifying", "yes|skip the confirmation"},
		legacy: []string{"keyring", "migrate"}},
	{path: "provider", group: groupSetup, short: "The Secret Service provider daemon"},
	{path: "provider serve", short: "Own org.freedesktop.secrets on this session bus", legacy: []string{"provider", "serve"}},
	{path: "provider status", short: "Show the current name owner and enabled state",
		flags: []string{"json|machine-readable output"}, legacy: []string{"provider", "status"}},
	{path: "provider enable", short: "Install the activation file and systemd user unit", legacy: []string{"provider", "enable"}},
	{path: "provider disable", short: "Stop the daemon and remove activation files", legacy: []string{"provider", "disable"}},

	// ── Hidden: plumbing and the pre-revamp names, kept for one release ─────
	{path: "ipc", use: "<method> <json-args>", hidden: true, short: "JSON IPC for other plugins", legacy: []string{"ipc"}},
	{path: "jev", hidden: true, short: "Optional Jev decision layer", legacy: []string{"jev"}},
	{path: "clipclear", hidden: true, short: "Clear the clipboard if it still holds a secret", legacy: []string{"clipclear"}},
	{path: "version", hidden: true, short: "Print the version", legacy: []string{"version"}},
	{path: "ask-save", use: "<service> <account>", hidden: true, short: "Prompt for a secret and store it (use: set --ask)", legacy: []string{"ask-save"}},
	{path: "reveal", use: "<service> <account>", hidden: true, short: "Print a secret after presence (use: get --reveal)", legacy: []string{"reveal"}},
	{path: "resolve", use: "<service> <account>", hidden: true, short: "Resolve and cache a secret (use: get --resolve)", legacy: []string{"resolve"}},
	{path: "ping", hidden: true, short: "Health check (use: doctor ping)", legacy: []string{"ping"}},
	{path: "selftest", hidden: true, short: "Keyring round-trip (use: doctor selftest)", legacy: []string{"selftest"}},
	{path: "setup", hidden: true, short: "Onboarding (use: doctor setup)", legacy: []string{"setup"}},
	{path: "migrate", hidden: true, short: "Secret Service to native store (use: import secretservice)", legacy: []string{"migrate"}},
	{path: "mcp install-all", hidden: true, short: "Write MCP config for every known agent (use: mcp install --all)", legacy: []string{"mcp", "install-all"}},
	{path: "mcp install-detected", hidden: true, short: "Wire detected agents (use: mcp install --detected)", legacy: []string{"mcp", "install-detected"}},
}

// takeFlag removes every occurrence of name from args (stopping at "--") and
// reports whether it was present.
func takeFlag(args []string, name string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	for i, a := range args {
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		if a == name {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// rewriteGet folds `reveal` and `resolve` into `get`. Each keeps its own
// legacy handler — and with it its gate — so `get --reveal` is `reveal`,
// byte for byte, and plain `get` is untouched.
func rewriteGet(args []string) ([]string, error) {
	rest, reveal := takeFlag(args, "--reveal")
	rest, resolve := takeFlag(rest, "--resolve")
	switch {
	case reveal && resolve:
		return nil, fmt.Errorf("--reveal and --resolve are mutually exclusive")
	case reveal:
		return append([]string{"reveal"}, rest...), nil
	case resolve:
		return append([]string{"resolve"}, rest...), nil
	}
	return append([]string{"get"}, rest...), nil
}

// rewriteMCPInstall folds install-all and install-detected into install.
func rewriteMCPInstall(args []string) ([]string, error) {
	rest, detected := takeFlag(args, "--detected")
	rest, all := takeFlag(rest, "--all")
	switch {
	case detected && all:
		return nil, fmt.Errorf("--detected and --all are mutually exclusive")
	case detected:
		return append([]string{"mcp", "install-detected"}, rest...), nil
	case all:
		return append([]string{"mcp", "install-all"}, rest...), nil
	}
	return append([]string{"mcp", "install"}, args...), nil
}

// legacyArgv returns the legacy argv for an invocation of s with args.
func (s *cmdSpec) legacyArgv(args []string) ([]string, error) {
	if s.rewrite != nil {
		return s.rewrite(args)
	}
	return append(append([]string{}, s.legacy...), args...), nil
}

func wantsHelp(args []string) bool {
	return len(args) > 0 && (args[0] == "-h" || args[0] == "--help")
}

// runSpec is the RunE of every command.
func (s *cmdSpec) runSpec(cmd *cobra.Command, args []string) error {
	activeCmd = cmd
	if wantsHelp(args) {
		return cmd.Help()
	}
	// A group that serves (bare `mcp` runs the server) must not swallow a
	// mistyped subcommand: `omaseal mcp instal` is an error, not a server.
	if s.serve && !s.loose && len(args) > 0 && !strings.HasPrefix(args[0], "-") && cmd.HasSubCommands() {
		return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
	}
	if len(s.legacy) == 0 && s.rewrite == nil {
		// A pure group (`agent`, `import`, `provider`): bare shows help; an
		// unknown word is an error, as `omaseal agent bogus` always was.
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
		}
		return cmd.Help()
	}
	argv, err := s.legacyArgv(args)
	if err != nil {
		return err
	}
	// Spellings the legacy handler logs or branches on by name are passed as
	// typed, so audit lines for old invocations stay identical.
	if called := cmd.CalledAs(); called != cmd.Name() && (called == "op" || called == "bw" || called == "keep-alive") {
		if idx := strings.Count(s.path, " "); s.rewrite == nil && len(argv) > idx {
			argv[idx] = called
		}
	}
	legacyRun(argv)
	return nil
}

func newRootCmd() *cobra.Command {
	cobra.EnableCommandSorting = false
	root := &cobra.Command{
		Use:   appName,
		Short: "Your system keyring, for you and your AI agents",
		Long:  "OmaSeal — system keyring for Omarchy.\n\nStore API keys once, hand them to agents only when you allow it, and keep an audit trail.",
		Example: "  omaseal set openrouter default < key.txt\n" +
			"  omaseal run -e OPENROUTER_API_KEY=openrouter/default -- hermes\n" +
			"  omaseal agent mode ask 30\n" +
			"  omaseal doctor",
		RunE: func(cmd *cobra.Command, _ []string) error {
			activeCmd = cmd
			ui.Banner(cmd.OutOrStdout(), version, target())
			return cmd.Help()
		},
	}
	root.SetHelpCommandGroupID(groupSetup)
	root.SetCompletionCommandGroupID(groupSetup)
	root.AddGroup(
		&cobra.Group{ID: groupSecrets, Title: "Secrets"},
		&cobra.Group{ID: groupAgents, Title: "Agents"},
		&cobra.Group{ID: groupHealth, Title: "Health"},
		&cobra.Group{ID: groupSetup, Title: "Setup"},
	)

	nodes := map[string]*cobra.Command{"": root}
	for i := range cliSpecs {
		s := &cliSpecs[i]
		parentPath, name := "", s.path
		if i := strings.LastIndex(s.path, " "); i >= 0 {
			parentPath, name = s.path[:i], s.path[i+1:]
		}
		parent := nodes[parentPath]
		if parent == nil {
			panic("cli: parent of " + s.path + " not declared before it")
		}
		use := name
		if s.use != "" {
			use += " " + s.use
		}
		c := &cobra.Command{
			Use:                use,
			Short:              s.short,
			Long:               s.long,
			Example:            s.example,
			Aliases:            s.aliases,
			Hidden:             s.hidden,
			DisableFlagParsing: true, // the legacy handlers parse their own argv
			Args:               cobra.ArbitraryArgs,
			RunE:               s.runSpec,
		}
		if c.Long == "" {
			c.Long = s.short
		}
		if s.group != "" && parent == root && !s.hidden {
			c.GroupID = s.group
		}
		for _, f := range s.flags {
			name, desc, _ := strings.Cut(f, "|")
			// Declared for help only — DisableFlagParsing means cobra never
			// reads them.
			value := strings.HasSuffix(name, "=")
			name = strings.TrimSuffix(name, "=")
			switch {
			case value && len(name) == 1:
				c.Flags().StringP(name, name, "", desc)
			case value:
				c.Flags().String(name, "", desc)
			case len(name) == 1:
				c.Flags().BoolP(name, name, false, desc)
			default:
				c.Flags().Bool(name, false, desc)
			}
		}
		parent.AddCommand(c)
		nodes[s.path] = c
	}
	return root
}

// usage prints the usage of the command being run — called by the legacy
// handlers after an argument error.
func usage() {
	if activeCmd != nil {
		fmt.Fprint(os.Stderr, activeCmd.UsageString())
		return
	}
	fmt.Fprintln(os.Stderr, "Run `omaseal --help` for usage.")
}

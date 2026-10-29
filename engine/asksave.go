package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// askSaveCooldown paces popup requests — a cancelled dialog still burns the
// slot, so an agent can't spam prompts faster than the user can read them.
const askSaveCooldown = 5 * time.Second

// askSaveRateLimited enforces the cooldown via a runtime-dir stamp so CLI
// invocations (new process each call) and MCP calls share the limit.
func askSaveRateLimited() error {
	dir := agentRuntimeDir()
	stamp := filepath.Join(dir, "ask-save.stamp")
	now := time.Now()
	if raw, err := os.ReadFile(stamp); err == nil {
		if last, perr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); perr == nil {
			if wait := askSaveCooldown - now.Sub(time.Unix(last, 0)); wait > 0 {
				return newError("rate_limited", fmt.Sprintf("retry in %ds", int(wait.Seconds())+1),
					errors.New("prompted save requested too soon after the previous one"))
			}
		}
	}
	// Best-effort stamp — a throttle write failure must not fail the save.
	if err := os.MkdirAll(dir, 0o700); err == nil {
		_ = os.WriteFile(stamp, []byte(strconv.FormatInt(now.Unix(), 10)), 0o600)
	}
	return nil
}

// sanitizeAskDesc flattens agent-controlled dialog copy to one line:
// newlines and control bytes could fake extra prompt text or instructions
// in front of the user. Capped by runes so multibyte input never splits.
func sanitizeAskDesc(desc string) string {
	const maxDesc = 200
	flat := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, desc)
	if r := []rune(flat); len(r) > maxDesc {
		return string(r[:maxDesc])
	}
	return flat
}

// askSave collects a secret from the USER in a masked GUI dialog and stores
// it — the value never transits the requesting agent's context, tool call,
// or process args. desc is optional caller context shown in the dialog
// (agent-supplied, untrusted: sanitized, labelled, and capped here).
// Errors are typed so an agent gets a recovery path, not a bare failure.
func askSave(ctx context.Context, service, account, desc string) error {
	if !graphicalSession() {
		return newError("no_gui_session", "run `omaseal ask-save <service> <account>` from a desktop session, or `omaseal set` in a terminal",
			errNoGUIPrompter)
	}
	if err := askSaveRateLimited(); err != nil {
		return err
	}
	text := fmt.Sprintf("Enter the secret to save for %s/%s (requested by %s)", service, account, requesterName())
	if desc != "" {
		text += "\n\nAgent note (untrusted): " + sanitizeAskDesc(desc)
	}
	secret, err := guiPromptDesc(ctx, text)
	switch {
	case err == nil:
		// fall through to the store write
	case errors.Is(err, errPromptCancelled):
		return newError("prompt_cancelled", "the user can retry the save when ready", err)
	case errors.Is(err, errNoGUIPrompter), errors.Is(err, errGUIDisabled):
		return newError("no_gui_prompter", fmt.Sprintf("install zenity or pinentry, or run `omaseal set %s %s` in a terminal", service, account), err)
	default:
		return newError("prompt_failed", "omaseal doctor", err)
	}
	// Store errors (locked, keyring down) already carry typed codes. The
	// storeSet seam is the same one omaseal_set uses — tests mock it.
	if err := storeSet(service, account, secret); err != nil {
		return err
	}
	// A user-typed replacement completes the rotation, same as `set` —
	// clear a stale flag so read surfaces stop warning about a credential
	// that no longer exists. Best-effort: the save already succeeded.
	if err := UnflagRotation(service, account); err != nil {
		WriteLog("ask-save %s/%s: flag clear failed: %v", service, account, err)
	}
	return nil
}

// handleAskSave is the CLI surface for askSave — agents without MCP run
// `omaseal ask-save <service> <account>` and get exit 0 on save, nonzero on
// cancel/error. The dialog names the caller via the parent process.
func handleAskSave() {
	service, account, err := argCredentials(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(1)
	}
	start := time.Now()
	err = askSave(context.Background(), service, account, "")
	logOpResult("ask-save", service+"/"+account, start, err)
	if err != nil {
		printError("prompted save: ", err)
		os.Exit(1)
	}
	WriteLog("ask-save %s/%s", service, account)
	fmt.Println("ok")
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Jev is the optional hosted decision layer: a local companion script reads
// the manifest and keyring metadata (never secret values) and asks OpenRouter
// for rationale/confidence on audit findings. Core keyring behavior never
// depends on it. State lives in ~/.config/omaseal/jev.json — the companion
// and any future hook check `enabled` there and do nothing while disabled.
type JevState struct {
	Enabled   bool      `json:"enabled"`
	Decided   bool      `json:"decided"` // user expressed a preference; setup stops offering
	UpdatedAt time.Time `json:"updated_at"`
	// LastRunAt is stamped by the companion after each run so doctor/status can
	// distinguish "enabled and producing" from "enabled but never ran".
	LastRunAt time.Time `json:"last_run_at,omitempty"`
}

func jevStatePath() string {
	return filepath.Join(omasealConfigDir(), "jev.json")
}

// loadJevState returns the persisted state; missing or corrupt files mean
// "not enabled, not decided" — fail closed, offerable again.
func loadJevState() JevState {
	var st JevState
	data, err := os.ReadFile(jevStatePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(data, &st) // corrupt → zero state
	return st
}

func saveJevState(st JevState) error {
	st.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileMode(jevStatePath(), append(data, '\n'), 0o600)
}

// jevCredentialPresent reports whether any openrouter/* item exists in the
// keyring — metadata only, never resolves a value.
func jevCredentialPresent() bool {
	items, err := List("")
	if err != nil {
		return false
	}
	return jevCredentialPresentItems(items)
}

func jevCredentialPresentItems(items []Item) bool {
	for _, it := range items {
		if strings.EqualFold(it.Service, "openrouter") {
			return true
		}
	}
	return false
}

// shouldOfferJev gates the setup prompt: only when undecided, disabled, and a
// usable credential exists.
func shouldOfferJev(st JevState, credentialPresent bool) bool {
	return !st.Enabled && !st.Decided && credentialPresent
}

const jevDisclosure = `Jev is an optional decision layer for OmaSeal.

When enabled, a local companion script may send keyring METADATA (service/
account names, access counts, manifest rules) to OpenRouter to add rationale
and confidence to ` + "`omaseal manifest audit`" + ` findings.

  - Secret VALUES are never sent — the payload is metadata only.
  - Core keyring behavior never depends on Jev; audit works without it.
  - While disabled, nothing Jev-related runs or contacts the network.
  - Jev proposes; only a human applies (omaseal manifest apply).
`

func handleJev() {
	sub := "status"
	for _, a := range os.Args[2:] {
		if !strings.HasPrefix(a, "-") {
			sub = strings.ToLower(a)
			break
		}
	}
	switch sub {
	case "enable":
		fmt.Fprint(os.Stderr, jevDisclosure)
		if !jevCredentialPresent() {
			fmt.Fprintln(os.Stderr, "warning: no openrouter/* item found in the keyring —")
			fmt.Fprintln(os.Stderr, "         the companion needs one (e.g. omaseal set openrouter default).")
		}
		// Enabling opts keyring metadata into an LLM call path — a typed "yes"
		// on a forgeable pty is not enough; require proof the local user
		// responded (fingerprint or GUI confirm). Fail closed otherwise.
		if err := requirePresenceStrict(context.Background(), "enable Jev metadata sharing", "edit "+jevStatePath()+" directly"); err != nil {
			fmt.Fprintf(os.Stderr, "jev: %v\n", err)
			os.Exit(1)
		}
		st := loadJevState()
		st.Enabled, st.Decided = true, true
		if err := saveJevState(st); err != nil {
			fmt.Fprintf(os.Stderr, "could not save state: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "jev: enabled")
	case "disable":
		st := loadJevState()
		st.Enabled, st.Decided = false, true
		if err := saveJevState(st); err != nil {
			fmt.Fprintf(os.Stderr, "could not save state: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "jev: disabled")
	case "status":
		st := loadJevState()
		fmt.Printf("enabled:    %v\n", st.Enabled)
		fmt.Printf("decided:    %v\n", st.Decided)
		if !st.UpdatedAt.IsZero() {
			fmt.Printf("updated_at: %s\n", st.UpdatedAt.Format(time.RFC3339))
		}
		if !st.LastRunAt.IsZero() {
			fmt.Printf("last_run:   %s\n", st.LastRunAt.Format(time.RFC3339))
		}
		fmt.Printf("credential: %v\n", jevCredentialPresent())
		fmt.Printf("state_file: %s\n", jevStatePath())
	default:
		fmt.Fprintln(os.Stderr, "usage: omaseal jev [status|enable|disable]")
		os.Exit(1)
	}
}

// maybeOfferJev asks once during interactive setup, only when a usable
// OpenRouter credential exists and the user has not already decided. Decline
// is persisted (decided=true) so setup never nags. --yes cannot consent, so
// unattended runs stay undecided and just print the pointer.
func maybeOfferJev(yes bool) {
	st := loadJevState()
	if !shouldOfferJev(st, jevCredentialPresent()) {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "=== Jev (optional) ===")
	fmt.Fprint(os.Stderr, jevDisclosure)
	if yes {
		fmt.Fprintln(os.Stderr, "Unattended setup does not enable Jev. Run `omaseal jev enable` to opt in.")
		return
	}
	if confirmExplicit("Enable Jev?") {
		// Same bar as `jev enable`: a pty-typed "yes" is not presence.
		if err := requirePresenceStrict(context.Background(), "enable Jev metadata sharing", "edit "+jevStatePath()+" directly"); err != nil {
			fmt.Fprintf(os.Stderr, "  jev not enabled: %v\n", err)
			return
		}
		st.Enabled, st.Decided = true, true
		if err := saveJevState(st); err != nil {
			fmt.Fprintf(os.Stderr, "  could not save state: %v\n", err)
			return
		}
		fmt.Fprintln(os.Stderr, "  jev: enabled")
		return
	}
	st.Decided = true
	if err := saveJevState(st); err != nil {
		fmt.Fprintf(os.Stderr, "  could not save state: %v\n", err)
		return
	}
	fmt.Fprintln(os.Stderr, "  jev: staying disabled (won't ask again — `omaseal jev enable` opts in)")
}

// confirmExplicit is confirm: both now accept only an explicit yes. Kept as a
// separate name where opt-in consent must read as deliberate at the call site.
func confirmExplicit(question string) bool {
	return confirm(question)
}

// checkJev is an informational doctor line: always optional, fails only when
// enabled but the pieces the companion needs are missing.
func checkJev() checkResult {
	st := loadJevState()
	if !st.Enabled {
		return checkResult{name: "jev", ok: true, optional: true,
			message: "disabled (optional decision layer — `omaseal jev status`)"}
	}
	var problems []string
	if !jevCredentialPresent() {
		problems = append(problems, "enabled but no openrouter/* item in the keyring")
	}
	if !commandExists("omaseal-jev-audit") {
		problems = append(problems, "enabled but omaseal-jev-audit not on PATH (see contrib/)")
	}
	if len(problems) > 0 {
		return checkResult{name: "jev", ok: false, optional: true,
			message: strings.Join(problems, "\n")}
	}
	lastRun := "never run"
	if !st.LastRunAt.IsZero() {
		lastRun = "last run " + st.LastRunAt.Format("2006-01-02 15:04")
	}
	return checkResult{name: "jev", ok: true, optional: true,
		message: "enabled — metadata-only audits via OpenRouter (" + lastRun + ")"}
}

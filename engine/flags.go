package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RotationFlag marks a stored secret as needing rotation — e.g. an agent saw
// the value leak into a log, a transcript, or a file it should not have been
// written to. The flag is metadata only; it never blocks reads, because the
// caller may need the (still valid) old value to finish its work. Instead
// every read surface alerts: `get`/`resolve` print a stderr warning, `list`
// marks the row, and MCP reads append a warning block agents cannot miss.
// `set` clears the flag — storing a new value is the rotation.
type RotationFlag struct {
	Reason    string    `json:"reason,omitempty"`
	FlaggedAt time.Time `json:"flagged_at"`
	FlaggedBy string    `json:"flagged_by,omitempty"`
}

// flagsPath resolves the flag store beside the omaseal log file in the state
// dir. Flags live outside the keyring on purpose: flagging must not require
// unlocking a collection, and the file survives backend migration.
func flagsPath() (string, error) {
	dir, err := ensureLogDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "flags.json"), nil
}

// flagsFile is the seam tests substitute.
var flagsFile = flagsPath

func loadFlags() (map[string]RotationFlag, error) {
	path, err := flagsFile()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]RotationFlag{}, nil
		}
		return nil, err
	}
	flags := map[string]RotationFlag{}
	if err := json.Unmarshal(b, &flags); err != nil {
		return nil, fmt.Errorf("flags file corrupt: %w", err)
	}
	return flags, nil
}

func saveFlags(flags map[string]RotationFlag) error {
	path, err := flagsFile()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(flags, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// FlagRotation marks a secret for rotation. The secret must exist — flagging
// a typo'd name would leave the warning pointing at nothing.
func FlagRotation(service, account, reason, flaggedBy string) error {
	if flaggedBy == "" {
		flaggedBy = "cli"
	}
	items, err := listItems(service, "")
	if err != nil {
		return err
	}
	found := false
	for _, it := range items {
		if it.Service == service && it.Account == account {
			found = true
			break
		}
	}
	if !found {
		return newError("not_found", "omaseal set "+service+" "+account,
			fmt.Errorf("no secret stored for %s/%s", service, account))
	}
	flags, err := loadFlags()
	if err != nil {
		return err
	}
	flags[statKey(service, account)] = RotationFlag{
		Reason:    reason,
		FlaggedAt: time.Now().UTC(),
		FlaggedBy: flaggedBy,
	}
	return saveFlags(flags)
}

// UnflagRotation clears a rotation flag. A missing flag is not an error —
// the end state is identical.
func UnflagRotation(service, account string) error {
	flags, err := loadFlags()
	if err != nil {
		return err
	}
	delete(flags, statKey(service, account))
	return saveFlags(flags)
}

// RotationFlagFor returns the flag for one secret, or nil.
func RotationFlagFor(service, account string) *RotationFlag {
	flags, err := loadFlags()
	if err != nil {
		return nil
	}
	if f, ok := flags[statKey(service, account)]; ok {
		flag := f
		return &flag
	}
	return nil
}

// rotationWarning is the alert text read surfaces emit for flagged secrets.
// Stderr/content-block placement keeps secret values themselves clean.
func rotationWarning(service, account string) string {
	f := RotationFlagFor(service, account)
	if f == nil {
		return ""
	}
	msg := fmt.Sprintf("warning: %s/%s is flagged for rotation (flagged %s by %s)",
		service, account, f.FlaggedAt.Format("2006-01-02"), f.FlaggedBy)
	if f.Reason != "" {
		msg += ": " + f.Reason
	}
	return msg
}

// warnIfFlagged prints the rotation alert to stderr — callers that stream
// the secret on stdout keep it parseable.
func warnIfFlagged(service, account string) {
	if msg := rotationWarning(service, account); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
}

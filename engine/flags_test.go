package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubFlagsFile points the flag store at a temp file per test.
func stubFlagsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flags.json")
	old := flagsFile
	flagsFile = func() (string, error) { return path, nil }
	t.Cleanup(func() { flagsFile = old })
	return path
}

// stubListItem makes the list seam return a single stored secret so
// FlagRotation's existence check passes without a real keyring.
func stubListItem(t *testing.T, service, account string) {
	t.Helper()
	old := listItems
	listItems = func(svc, _ string) ([]Item, error) {
		if svc != "" && svc != service {
			return nil, nil
		}
		return []Item{{Service: service, Account: account, Owned: true}}, nil
	}
	t.Cleanup(func() { listItems = old })
}

func TestFlagsRoundTrip(t *testing.T) {
	stubFlagsFile(t)
	flags, err := loadFlags()
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if len(flags) != 0 {
		t.Fatalf("want empty flags, got %d", len(flags))
	}
	flags["svc/acct"] = RotationFlag{Reason: "leaked", FlaggedAt: time.Now().UTC(), FlaggedBy: "cli"}
	if err := saveFlags(flags); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadFlags()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	f, ok := got["svc/acct"]
	if !ok || f.Reason != "leaked" || f.FlaggedBy != "cli" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFlagRotationRequiresExistingSecret(t *testing.T) {
	stubFlagsFile(t)
	old := listItems
	listItems = func(string, string) ([]Item, error) { return nil, nil }
	t.Cleanup(func() { listItems = old })
	err := FlagRotation("ghost", "acct", "", "cli")
	if err == nil || codeFromError(err) != "not_found" {
		t.Fatalf("want not_found, got %v", err)
	}
}

func TestFlagAndUnflag(t *testing.T) {
	stubFlagsFile(t)
	stubListItem(t, "svc", "acct")
	if err := FlagRotation("svc", "acct", "token in log", "cli"); err != nil {
		t.Fatalf("flag: %v", err)
	}
	f := RotationFlagFor("svc", "acct")
	if f == nil || f.Reason != "token in log" {
		t.Fatalf("want flag with reason, got %+v", f)
	}
	if msg := rotationWarning("svc", "acct"); !strings.Contains(msg, "flagged for rotation") || !strings.Contains(msg, "token in log") {
		t.Fatalf("warning missing detail: %q", msg)
	}
	if err := UnflagRotation("svc", "acct"); err != nil {
		t.Fatalf("unflag: %v", err)
	}
	if RotationFlagFor("svc", "acct") != nil {
		t.Fatal("flag survived unflag")
	}
	if rotationWarning("svc", "acct") != "" {
		t.Fatal("warning emitted for unflagged secret")
	}
	// Unflag of a never-flagged secret is a no-op, not an error.
	if err := UnflagRotation("svc", "acct"); err != nil {
		t.Fatalf("idempotent unflag: %v", err)
	}
}

func TestCorruptFlagsFileFails(t *testing.T) {
	path := stubFlagsFile(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFlags(); err == nil {
		t.Fatal("corrupt flags file must error, not silently reset")
	}
}

func TestEnrichItemsWithFlags(t *testing.T) {
	stubFlagsFile(t)
	stubListItem(t, "svc", "acct")
	if err := FlagRotation("svc", "acct", "x", "cli"); err != nil {
		t.Fatalf("flag: %v", err)
	}
	items := []Item{
		{Service: "svc", Account: "acct"},
		{Service: "other", Account: "acct"},
	}
	items = EnrichItemsWithFlags(items)
	if !items[0].RotationFlagged || items[0].RotationReason != "x" {
		t.Fatalf("flagged item not enriched: %+v", items[0])
	}
	if items[1].RotationFlagged {
		t.Fatal("unflagged item marked")
	}
}

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
)

// backendmigrate.go implements `omaseal migrate` — a one-shot bulk copy from
// Secret Service into the native store. Copy-only: the source is never
// written, so rollback stays a `backend: secretservice` config flip
// (docs/plans/2026-10-04-001-feat-backend-migrate-plan.md, KTD-1).

// itemSource is the read side of a migration. ssStore satisfies it; tests
// inject a fake so the migrate core runs without D-Bus (KTD-5).
type itemSource interface {
	List(service string) ([]Item, error)
	Get(service, account string) (string, error)
}

// migrateSummary is the report `omaseal migrate` prints and logs.
type migrateSummary struct {
	Migrated    int
	Skipped     int
	Failed      int
	FailedItems []string
}

// maxConsecGetFailures stops the batch when the source looks dead — per-item
// isolation (R4) covers a bad item, not a daemon that stopped answering.
const maxConsecGetFailures = 8

// migrateItems copies every addressable source item into dst. An item whose
// key already exists in dst is skipped (idempotent re-runs, R3); a Get or
// write failure for one item is recorded and never aborts the batch (R4).
// dryRun counts what would happen without reading or writing a single value.
func migrateItems(src itemSource, dst *nativeStore, dryRun bool) (*migrateSummary, error) {
	// Init first: on TTY this runs the passphrase flow before any source
	// work; non-TTY on an uninitialized store fails closed with the hint
	// (R6) — and an initialized store answers List without unlock anyway.
	if err := dst.ensureInit(); err != nil {
		return nil, err
	}
	existing, err := dst.List("")
	if err != nil {
		return nil, err
	}
	present := make(map[string]bool, len(existing))
	for _, it := range existing {
		present[nativeKey(it.Service, it.Account)] = true
	}

	items, err := src.List("")
	if err != nil {
		return nil, fmt.Errorf("enumerate source: %w", err)
	}

	res := &migrateSummary{}
	fail := func(key string, err error) {
		res.Failed++
		res.FailedItems = append(res.FailedItems, sanitizeField(key))
		WriteLog("op=migrate item_failed key=%s err=%s", sanitizeField(key), sanitizeField(err.Error()))
	}

	// Several physical items can share service/account (different writers
	// stamped the same attributes). Collapse to one entry per key, preferring
	// the OmaSeal-owned record — the same preference findItem applies to
	// reads, so the provenance flag and the value agree.
	byKey := make(map[string]Item, len(items))
	for _, it := range items {
		if it.Service == "" || it.Account == "" {
			continue // unaddressable — same rule List applies
		}
		key := nativeKey(it.Service, it.Account)
		if prev, ok := byKey[key]; !ok || (it.Owned && !prev.Owned) {
			byKey[key] = it
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	consec := 0
	for i, key := range keys {
		if i > 0 && i%100 == 0 {
			fmt.Fprintf(os.Stderr, "  … %d/%d\n", i, len(keys))
		}
		if present[key] {
			res.Skipped++
			continue
		}
		if dryRun {
			res.Migrated++
			continue
		}
		it := byKey[key]
		secret, err := src.Get(it.Service, it.Account)
		if err != nil {
			fail(key, err)
			consec++
			if consec >= maxConsecGetFailures {
				return res, fmt.Errorf("aborting: %d consecutive source reads failed — the Secret Service daemon looks dead", consec)
			}
			continue
		}
		consec = 0
		switch err := dst.migrateSet(it.Service, it.Account, secret, it.Owned); {
		case err == nil:
			res.Migrated++
		case errors.Is(err, errItemExists):
			// A concurrent writer landed between our snapshot and the write —
			// their value wins, we count it skipped (TOCTOU guard).
			res.Skipped++
		default:
			fail(key, err)
		}
	}
	return res, nil
}

// printSummary reports a (possibly partial) migration result: stdout gets the
// counts, stderr the named failures.
func printSummary(res *migrateSummary) {
	fmt.Printf("migrated %d, skipped %d, failed %d\n", res.Migrated, res.Skipped, res.Failed)
	for _, name := range res.FailedItems {
		fmt.Fprintf(os.Stderr, "  failed: %s\n", name)
	}
}

// handleMigrate runs `omaseal migrate` — copy every Secret Service item into
// the native store. Source and target are constructed directly so the command
// works before or after `backend:` flips (KTD-4).
func handleMigrate(args []string) {
	var dryRun, yes bool
	for _, a := range args {
		switch a {
		case "--dry-run":
			dryRun = true
		case "-y", "--yes":
			yes = true
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			fmt.Fprintln(os.Stderr, "usage: omaseal migrate [--dry-run] [-y|--yes]")
			os.Exit(1)
		}
	}

	// Self-serve guard: if our own provider daemon owns org.freedesktop.secrets
	// — or an omaseal activation is installed that could take the name
	// mid-migrate — migrate would read OmaSeal back into itself. Require an
	// explicit disable rather than silently looping the same store.
	// The activation check reads a local file — it must run even when no
	// session bus is reachable, or migrate fails open and can self-serve.
	if svcActivationIsOurs() {
		fmt.Fprintf(os.Stderr, "error: an omaseal activation file is installed at %s — it can claim %s mid-migrate and self-serve.\n", svcActivationPath(), svcBusName)
		fmt.Fprintln(os.Stderr, "Run `omaseal provider disable` first, then retry.")
		os.Exit(1)
	}
	if conn, err := svcConnect(""); err == nil {
		defer func() { _ = conn.Close() }()
		if ours, owner, _ := svcOwnerIsOurs(conn); ours {
			fmt.Fprintf(os.Stderr, "error: %s is owned by this omaseal daemon (%s) — migrate would self-serve.\n", svcBusName, owner)
			fmt.Fprintln(os.Stderr, "Run `omaseal provider disable` first, then retry.")
			os.Exit(1)
		}
	}

	dst := newNativeStore()
	src := ssStore{}

	if !yes && !dryRun {
		res, err := migrateItems(src, dst, true)
		if err != nil {
			printError("migrate: ", err)
			os.Exit(1)
		}
		if res.Migrated == 0 && res.Failed == 0 {
			fmt.Println("nothing to migrate — the native store already covers the source")
			return
		}
		fmt.Fprintf(os.Stderr, "Will copy %d secrets from Secret Service into the native store (%d already present).\nThe source keyring is never modified — rollback is `backend: secretservice`.\n", res.Migrated, res.Skipped)
		if !confirm("Proceed? [Y/n] ") {
			fmt.Fprintln(os.Stderr, "aborted")
			return
		}
	}

	res, err := migrateItems(src, dst, dryRun)
	if err != nil {
		if res != nil {
			WriteLog("op=migrate aborted migrated=%d skipped=%d failed=%d: %s",
				res.Migrated, res.Skipped, res.Failed, sanitizeField(err.Error()))
			printSummary(res)
		} else {
			WriteLog("op=migrate aborted: %s", sanitizeField(err.Error()))
		}
		printError("migrate: ", err)
		os.Exit(1)
	}
	if dryRun {
		WriteLog("op=migrate dry_run=true migrated=%d skipped=%d failed=%d", res.Migrated, res.Skipped, res.Failed)
		fmt.Printf("dry run: would copy %d, skip %d, fail %d\n", res.Migrated, res.Skipped, res.Failed)
		return
	}
	WriteLog("op=migrate migrated=%d skipped=%d failed=%d", res.Migrated, res.Skipped, res.Failed)
	printSummary(res)
	if res.Failed > 0 {
		os.Exit(1)
	}
}

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/godbus/dbus/v5"
	ss "github.com/zalando/go-keyring/secret_service"
)

// Keyring at-rest encryption migration.
//
// gnome-keyring has no ChangePassword in the Secret Service API, so the only
// path from a plaintext (empty-password) keyring to an encrypted one is
// create -> copy -> repoint -> delete. The daemon prompts for the new
// keyring's password itself via its GUI prompter during CreateCollection;
// omaseal never sees it.
//
// Empirical daemon quirks this code accounts for:
//   - CreateCollection rejects aliases other than "default"; create
//     unaliased, then SetAlias after the copy verifies.
//   - The Items property can list stale paths that fail on property read;
//     resolve lazily and skip them rather than aborting.
//   - CreateItem is called with replace=true, so items sharing an identical
//     attribute dict merge into one; landed count can legitimately be lower
//     than copied count — compare against the distinct-attribute count.

const (
	serviceInterface  = "org.freedesktop.Secret.Service"
	servicePath       = "/org/freedesktop/secrets"
	promptInterface   = "org.freedesktop.Secret.Prompt"
	propertiesIface   = "org.freedesktop.DBus.Properties"
	collectionBase    = "/org/freedesktop/secrets/collection/"
	defaultAliasPath  = "/org/freedesktop/secrets/aliases/default"
	promptWaitTimeout = 2 * time.Minute
)

// itemRef is a resolved keyring item: everything needed to recreate it.
type itemRef struct {
	path       dbus.ObjectPath
	label      string
	attributes map[string]string
}

// migrateResult reports what a migration did (or would do, when DryRun).
type migrateResult struct {
	SourceCollection dbus.ObjectPath
	NewCollection    dbus.ObjectPath
	SourceItems      int // resolvable items found in source
	StaleSkipped     int // item paths that failed to resolve
	Copied           int
	Landed           int // items present in the new collection after copy
	Merged           int // copied items that merged onto identical attributes
	AliasRepointed   bool
	OldDeleted       bool
	DryRun           bool
}

// promptAndWait drives an org.freedesktop.Secret.Prompt to completion with a
// bound. The vendored secret_service package's handlePrompt is unexported and
// waits on the Completed signal with no timeout; this mirrors it with a
// deadline so a prompt that can never render cannot hang the command.
func promptAndWait(svc *ss.SecretService, prompt dbus.ObjectPath, timeout time.Duration) (bool, dbus.Variant, error) {
	if prompt == "/" || prompt == "" {
		return false, dbus.MakeVariant(""), nil
	}
	matchOpts := []dbus.MatchOption{
		dbus.WithMatchObjectPath(prompt),
		dbus.WithMatchInterface(promptInterface),
	}
	if err := svc.AddMatchSignal(matchOpts...); err != nil {
		return false, dbus.Variant{}, err
	}
	defer func() { _ = svc.RemoveMatchSignal(matchOpts...) }()

	sigCh := make(chan *dbus.Signal, 1)
	svc.Signal(sigCh)
	defer svc.RemoveSignal(sigCh)

	if err := svc.Object(secretServiceName, prompt).Call(promptInterface+".Prompt", 0, "").Err; err != nil {
		return false, dbus.Variant{}, err
	}

	select {
	case sig := <-sigCh:
		if sig.Name != promptInterface+".Completed" {
			return false, dbus.Variant{}, fmt.Errorf("unexpected prompt signal %q", sig.Name)
		}
		dismissed, _ := sig.Body[0].(bool)
		result, _ := sig.Body[1].(dbus.Variant)
		return dismissed, result, nil
	case <-time.After(timeout):
		return false, dbus.Variant{}, fmt.Errorf("keyring prompt timed out after %s", timeout)
	}
}

// serviceObject returns the /org/freedesktop/secrets service object.
func serviceObject(svc *ss.SecretService) dbus.BusObject {
	return svc.Object(secretServiceName, dbus.ObjectPath(servicePath))
}

// createCollection calls Service.CreateCollection with an empty alias
// (gnome-keyring accepts only "default" there) and drives the password
// prompt to completion with a bound.
func createCollection(svc *ss.SecretService, label string) (dbus.ObjectPath, error) {
	props := map[string]dbus.Variant{
		collectionInterface + ".Label": dbus.MakeVariant(label),
	}
	var collection, prompt dbus.ObjectPath
	err := serviceObject(svc).Call(serviceInterface+".CreateCollection", 0, props, "").Store(&collection, &prompt)
	if err != nil {
		return "", err
	}
	if len(collection) > 1 {
		return collection, nil
	}
	dismissed, result, err := promptAndWait(svc, prompt, promptWaitTimeout)
	if err != nil {
		return "", err
	}
	if dismissed {
		return "", errors.New("keyring password prompt was dismissed")
	}
	p, ok := result.Value().(dbus.ObjectPath)
	if !ok || len(p) <= 1 {
		return "", fmt.Errorf("unexpected CreateCollection result %v", result)
	}
	return p, nil
}

// collectionObject wraps a collection path in a BusObject.
func collectionObject(svc *ss.SecretService, path dbus.ObjectPath) dbus.BusObject {
	return svc.Object(secretServiceName, path)
}

// currentDefault resolves the collection the "default" alias points at.
func currentDefault(svc *ss.SecretService) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	if err := serviceObject(svc).Call(serviceInterface+".ReadAlias", 0, "default").Store(&path); err != nil {
		return "", err
	}
	return path, nil
}

// enumerateItems reads the collection's Items property and resolves each
// path's label and attributes lazily. Paths that fail to resolve (stale
// entries observed in the wild) are counted in stale and skipped.
func enumerateItems(svc *ss.SecretService, collection dbus.BusObject) (items []itemRef, stale int, err error) {
	var v dbus.Variant
	if err := collection.Call(propertiesIface+".Get", 0, collectionInterface, "Items").Store(&v); err != nil {
		return nil, 0, fmt.Errorf("read Items: %w", err)
	}
	paths, ok := v.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, 0, fmt.Errorf("unexpected Items property type %T", v.Value())
	}
	for _, p := range paths {
		obj := svc.Object(secretServiceName, p)
		var labelV, attrsV dbus.Variant
		if err := obj.Call(propertiesIface+".Get", 0, itemInterface, "Label").Store(&labelV); err != nil {
			stale++
			continue
		}
		if err := obj.Call(propertiesIface+".Get", 0, itemInterface, "Attributes").Store(&attrsV); err != nil {
			stale++
			continue
		}
		label, _ := labelV.Value().(string)
		attrs, _ := attrsV.Value().(map[string]string)
		if attrs == nil {
			attrs = map[string]string{}
		}
		items = append(items, itemRef{path: p, label: label, attributes: attrs})
	}
	return items, stale, nil
}

// attrKey renders an attribute dict as a canonical comparable key.
func attrKey(attrs map[string]string) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	key := ""
	for _, k := range keys {
		key += k + "\x00" + attrs[k] + "\x00"
	}
	return key
}

// distinctAttrCount returns the number of unique attribute dicts — the
// expected landed count, since CreateItem(replace=true) merges items that
// share identical attributes.
func distinctAttrCount(items []itemRef) int {
	seen := make(map[string]struct{}, len(items))
	for _, it := range items {
		seen[attrKey(it.attributes)] = struct{}{}
	}
	return len(seen)
}

// copyItems writes every item into the destination collection, reading each
// secret with the given session path.
func copyItems(svc *ss.SecretService, dst dbus.BusObject, items []itemRef, session dbus.ObjectPath) (copied int, err error) {
	for _, it := range items {
		secret, err := svc.GetSecret(it.path, session)
		if err != nil {
			return copied, fmt.Errorf("read secret for %q: %w", it.label, err)
		}
		if err := svc.CreateItem(dst, it.label, it.attributes, *secret); err != nil {
			return copied, fmt.Errorf("write %q: %w", it.label, err)
		}
		copied++
	}
	return copied, nil
}

// checkLanded validates post-copy state: landed must cover every distinct
// attribute dict (merges are expected, shortfalls are not), and the
// destination must not contain unresolvable items.
func checkLanded(items []itemRef, copied, landed, staleDst int) error {
	want := distinctAttrCount(items)
	if landed < want {
		return fmt.Errorf("verification failed: %d items landed, want >= %d distinct", landed, want)
	}
	if staleDst > 0 {
		return fmt.Errorf("verification failed: %d unresolvable items in new keyring", staleDst)
	}
	return nil
}

// setDefaultAlias points the "default" alias at path.
func setDefaultAlias(svc *ss.SecretService, path dbus.ObjectPath) error {
	return serviceObject(svc).Call(serviceInterface+".SetAlias", 0, "default", path).Err
}

// deleteCollection removes a collection and its backing file. The daemon may
// return a confirmation prompt; it is driven with the same bound.
func deleteCollection(svc *ss.SecretService, path dbus.ObjectPath) error {
	var prompt dbus.ObjectPath
	if err := collectionObject(svc, path).Call(collectionInterface+".Delete", 0).Store(&prompt); err != nil {
		return err
	}
	dismissed, _, err := promptAndWait(svc, prompt, promptWaitTimeout)
	if err != nil {
		return err
	}
	if dismissed {
		return errors.New("delete confirmation prompt was dismissed")
	}
	return nil
}

// migrateKeyring copies the current default collection into a new "login"
// collection and repoints the default alias. In dryRun it stops after
// enumeration. When deleteOld is set, the source collection is removed only
// after the copy verifies.
func migrateKeyring(dryRun, deleteOld bool) (*migrateResult, error) {
	if !graphicalSession() {
		return nil, errors.New("no graphical session detected — the daemon must prompt for the new keyring password via GUI; run this inside a graphical session")
	}

	svc, err := ss.NewSecretService()
	if err != nil {
		return nil, keyringError(err)
	}

	srcPath, err := currentDefault(svc)
	if err != nil {
		return nil, fmt.Errorf("resolve default collection: %w", err)
	}
	res := &migrateResult{SourceCollection: srcPath, DryRun: dryRun}

	// CreateCollection("login") returns the existing collection when one
	// with that label exists; if the default already IS it, a migrate would
	// copy the keyring onto itself.
	if srcPath == dbus.ObjectPath(collectionBase+"login") {
		return res, errors.New("default is already the 'login' keyring — nothing to migrate")
	}

	src := collectionObject(svc, srcPath)
	if err := svc.Unlock(srcPath); err != nil {
		return nil, fmt.Errorf("unlock source collection: %w", err)
	}

	items, stale, err := enumerateItems(svc, src)
	if err != nil {
		return nil, err
	}
	res.SourceItems = len(items)
	res.StaleSkipped = stale
	if dryRun {
		return res, nil
	}

	newPath, err := createCollection(svc, "login")
	if err != nil {
		return nil, fmt.Errorf("create encrypted keyring: %w", err)
	}
	res.NewCollection = newPath
	dst := collectionObject(svc, newPath)

	session, err := svc.OpenSession()
	if err != nil {
		return nil, fmt.Errorf("open secret session: %w", err)
	}
	defer svc.Close(session)

	res.Copied, err = copyItems(svc, dst, items, session.Path())
	if err != nil {
		return res, err
	}

	landed, staleDst, err := enumerateItems(svc, dst)
	if err != nil {
		return res, fmt.Errorf("verify new keyring: %w", err)
	}
	res.Landed = len(landed)
	res.Merged = res.Copied - res.Landed
	if err := checkLanded(items, res.Copied, res.Landed, staleDst); err != nil {
		return res, err
	}

	if err := setDefaultAlias(svc, newPath); err != nil {
		return res, fmt.Errorf("repoint default alias: %w", err)
	}
	res.AliasRepointed = true

	if deleteOld {
		if err := deleteCollection(svc, srcPath); err != nil {
			return res, fmt.Errorf("delete old keyring: %w", err)
		}
		res.OldDeleted = true
	}
	return res, nil
}

// keyringStatus reports the default collection path and item count for
// `omaseal keyring status`.
func keyringStatus() error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return keyringError(err)
	}
	path, err := currentDefault(svc)
	if err != nil {
		return err
	}
	items, stale, err := enumerateItems(svc, collectionObject(svc, path))
	if err != nil {
		return err
	}
	fmt.Printf("default collection: %s\nitems: %d resolvable", path, len(items))
	if stale > 0 {
		fmt.Printf(" (%d stale paths skipped)", stale)
	}
	fmt.Println()
	return nil
}

// --- CLI surface -----------------------------------------------------------

// runKeyring dispatches `omaseal keyring <sub>` subcommands.
func runKeyring(args []string) {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status":
		if err := keyringStatus(); err != nil {
			printError("keyring status: ", err)
			os.Exit(1)
		}
	case "migrate":
		runMigrate(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "usage: omaseal keyring <migrate|status>")
		fmt.Fprintln(os.Stderr, "  omaseal keyring migrate [--dry-run] [--delete-old] [-y|--yes]")
		os.Exit(1)
	}
}

// runMigrate drives `omaseal keyring migrate`. Default flow: enumerate, show
// the plan, confirm, then migrate. --dry-run stops after enumeration;
// --delete-old removes the source collection only after verify; -y skips the
// interactive confirmation (scripted use — the daemon still prompts for the
// new keyring's password itself).
func runMigrate(args []string) {
	var dryRun, deleteOld, yes bool
	for _, a := range args {
		switch a {
		case "--dry-run":
			dryRun = true
		case "--delete-old":
			deleteOld = true
		case "-y", "--yes":
			yes = true
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			fmt.Fprintln(os.Stderr, "usage: omaseal keyring migrate [--dry-run] [--delete-old] [-y|--yes]")
			os.Exit(1)
		}
	}

	if !graphicalSession() {
		fmt.Fprintln(os.Stderr, "error: no graphical session detected — the daemon must prompt for the new keyring password via GUI; run this inside a graphical session")
		os.Exit(1)
	}

	// Enumerate first so the confirmation shows real numbers. migrateKeyring
	// re-enumerates internally; a dry run is just migrateKeyring(dryRun=true)
	// with output, so do a probe pass only when we need to ask.
	if !yes && !dryRun {
		res, err := migrateKeyring(true, false)
		if err != nil {
			printError("reading keyring: ", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Will migrate %d secrets from %s into a new encrypted 'login' keyring.\n", res.SourceItems, res.SourceCollection)
		fmt.Fprintln(os.Stderr, "The daemon will prompt you for the new keyring password — use your login password so PAM can auto-unlock it.")
		if deleteOld {
			fmt.Fprintln(os.Stderr, "After verifying, the old plaintext keyring will be deleted.")
		}
		if !confirm("Proceed?") {
			fmt.Fprintln(os.Stderr, "aborted")
			return
		}
	}

	res, err := migrateKeyring(dryRun, deleteOld)
	if err != nil {
		printError("migrate: ", err)
		if res != nil && res.Copied > 0 {
			fmt.Fprintf(os.Stderr, "partial state: copied %d, landed %d — old keyring untouched, safe to re-run\n", res.Copied, res.Landed)
		}
		os.Exit(1)
	}

	if dryRun {
		fmt.Printf("dry-run: %d secrets in %s", res.SourceItems, res.SourceCollection)
		if res.StaleSkipped > 0 {
			fmt.Printf(" (%d stale paths skipped)", res.StaleSkipped)
		}
		fmt.Println(" — nothing changed")
		return
	}

	fmt.Printf("migrated: %d secrets -> %s", res.Copied, res.NewCollection)
	if res.Merged > 0 {
		fmt.Printf(" (%d landed as %d, merged identical-attribute items)", res.Copied, res.Landed)
	}
	fmt.Println()
	fmt.Printf("default alias -> %s\n", res.NewCollection)
	if res.OldDeleted {
		fmt.Println("old plaintext keyring deleted")
	} else {
		fmt.Println("old keyring kept (still plaintext on disk) — re-run with --delete-old to remove it")
	}
	fmt.Println("next: disable display-manager autologin so your login password reaches PAM at boot, then `omaseal doctor` to verify")
	WriteLog("keyring migrate: %d copied, %d landed, alias repointed, deleted=%v", res.Copied, res.Landed, res.OldDeleted)
}

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/zalando/go-keyring"
	ss "github.com/zalando/go-keyring/secret_service"
)

const (
	// appAttribute marks items OmaSeal itself wrote, as provenance. Reads and
	// updates match on service/account alone so items written by other tools
	// (omarchy-secrets-*, keytar, seahorse) share the same namespace.
	// appAttributeVal is intentionally still "oma-ring" so secrets stored before
	// the rename keep consistent metadata; the label (visible in keyring UIs)
	// uses the new name.
	appAttribute    = "app"
	appAttributeVal = "oma-ring"

	secretServiceName   = "org.freedesktop.secrets"
	collectionInterface = "org.freedesktop.Secret.Collection"
	itemInterface       = "org.freedesktop.Secret.Item"
)

// Item is metadata for a stored secret. It intentionally does not include the
// secret value; callers must explicitly request that with GetSecret.
type Item struct {
	Service      string     `json:"service"`
	Account      string     `json:"account"`
	Label        string     `json:"label"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	AccessCount  int        `json:"access_count,omitempty"`
	LastAccessed *time.Time `json:"last_accessed,omitempty"`
	// Owned marks items written by OmaSeal (app=oma-ring). Items sharing the
	// service/account namespace but written by other tools report false so
	// consumers can distinguish provenance before mutating them.
	Owned bool `json:"owned"`
	// RotationFlagged marks secrets a caller flagged for rotation via
	// `omaseal flag`; RotationReason carries the optional note. Read
	// surfaces alert on these — the value itself is still served.
	RotationFlagged bool   `json:"rotation_flagged,omitempty"`
	RotationReason  string `json:"rotation_reason,omitempty"`
}

// keyringError wraps keyring failures with actionable context.
func keyringError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, keyring.ErrNotFound) {
		return newError("not_found", "omaseal set", err)
	}
	if errors.Is(err, errKeyringTimeout) {
		return newError("keyring_timeout", "retry, or restart gnome-keyring — see omaseal doctor", err)
	}
	return newError("keyring_unavailable", "omaseal doctor", fmt.Errorf("keyring: %w", err))
}

// errKeyringTimeout marks operations that exceeded their deadline against the
// Secret Service daemon. Callers can errors.Is it to distinguish a wedged
// daemon from a real failure — a wedged daemon must fail fast instead of
// parking the caller (and any agent tool call behind it) forever.
var errKeyringTimeout = errors.New("keyring operation timed out")

// Calls that never surface a user prompt get a short deadline: connect,
// search, session open, and property reads are pure daemon round-trips.
const keyringOpTimeout = 12 * time.Second

// Calls that can surface a gcr unlock/create prompt get a human-scale
// deadline so a legitimate prompt still completes — but an orphaned prompt
// (daemon restart, stale bus-name owner) cannot wedge the process for hours.
const keyringPromptTimeout = 2 * time.Minute

// callWithTimeout runs fn in a goroutine and abandons it after d. The
// zalando secret_service methods take no context, so a goroutine+select is
// the only way to bound them; the abandoned call's reply is harmless — godbus
// drops it once nobody reads the result channel.
func callWithTimeout[T any](op string, d time.Duration, fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := fn()
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-time.After(d):
		var zero T
		return zero, fmt.Errorf("%w: %s exceeded %s", errKeyringTimeout, op, d)
	}
}

func runWithTimeout(op string, d time.Duration, fn func() error) error {
	_, err := callWithTimeout(op, d, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

// keyringStore returns a connected SecretService and the default collection.
func keyringStore() (*ss.SecretService, dbus.BusObject, error) {
	svc, err := callWithTimeout("connect", keyringOpTimeout, func() (*ss.SecretService, error) {
		return ss.NewSecretService()
	})
	if err != nil {
		return nil, nil, keyringError(err)
	}
	collection := svc.GetLoginCollection()
	if err := runWithTimeout("unlock collection", keyringPromptTimeout, func() error {
		return svc.Unlock(collection.Path())
	}); err != nil {
		return nil, nil, keyringError(err)
	}
	return svc, collection, nil
}

// findItems returns every item matching service and account, regardless of
// which tool wrote it. Several physical items can share the pair (different
// writers stamped the same attributes).
func findItems(svc *ss.SecretService, collection dbus.BusObject, service, account string) ([]dbus.ObjectPath, error) {
	search := map[string]string{
		"service": service,
		"account": account,
	}
	paths, err := callWithTimeout("search items", keyringOpTimeout, func() ([]dbus.ObjectPath, error) {
		return svc.SearchItems(collection, search)
	})
	if err != nil {
		return nil, keyringError(err)
	}
	if len(paths) == 0 {
		return nil, keyringError(keyring.ErrNotFound)
	}
	return paths, nil
}

// findItem returns the single item matching service and account for reads.
// When several items collide on those attributes, the OmaSeal-owned one wins
// so reads prefer the item this tool manages.
func findItem(svc *ss.SecretService, collection dbus.BusObject, service, account string) (dbus.ObjectPath, error) {
	paths, err := findItems(svc, collection, service, account)
	if err != nil {
		return "", err
	}
	if len(paths) == 1 {
		return paths[0], nil
	}
	for _, p := range paths {
		if attrs, err := itemAttributes(svc, p); err == nil && attrs[appAttribute] == appAttributeVal {
			return p, nil
		}
	}
	return paths[0], nil
}

// Set stores a secret under service and account.
func (ssStore) Set(service, account, secret string) error {
	if service == "" || account == "" || secret == "" {
		return errors.New("service, account, and secret must not be empty")
	}

	svc, collection, err := keyringStore()
	if err != nil {
		return err
	}

	session, err := callWithTimeout("open session", keyringOpTimeout, func() (dbus.BusObject, error) {
		return svc.OpenSession()
	})
	if err != nil {
		return keyringError(err)
	}
	defer runWithTimeout("close session", keyringOpTimeout, func() error {
		return svc.Close(session)
	})

	// Existing items addressed by service/account are updated in place,
	// preserving whatever attributes they carry — including foreign ones, so
	// updating an omarchy-secrets or keytar item never creates a duplicate
	// beside it. When several items collide on the pair, all copies are
	// updated so any subsequent read returns the new value regardless of
	// which physical item it lands on.
	if paths, err := findItems(svc, collection, service, account); err == nil {
		var setErr error
		for _, p := range paths {
			obj := svc.Object(secretServiceName, p)
			if callErr := runWithTimeout("set secret", keyringPromptTimeout, func() error {
				return obj.Call(itemInterface+".SetSecret", 0, ss.NewSecret(session.Path(), secret)).Err
			}); callErr != nil {
				setErr = callErr
			}
		}
		return keyringError(setErr)
	} else if !errors.Is(err, keyring.ErrNotFound) {
		return err
	}

	attributes := map[string]string{
		appAttribute: appAttributeVal,
		"service":    service,
		"account":    account,
	}
	label := fmt.Sprintf("OmaSeal: %s / %s", service, account)

	if err := runWithTimeout("create item", keyringPromptTimeout, func() error {
		return svc.CreateItem(collection, label, attributes, ss.NewSecret(session.Path(), secret))
	}); err != nil {
		return keyringError(err)
	}
	return nil
}

// Get retrieves the secret for service and account.
func (ssStore) Get(service, account string) (string, error) {
	if service == "" || account == "" {
		return "", errors.New("service and account must not be empty")
	}

	svc, collection, err := keyringStore()
	if err != nil {
		return "", err
	}

	p, err := findItem(svc, collection, service, account)
	if err != nil {
		return "", err
	}

	session, err := callWithTimeout("open session", keyringOpTimeout, func() (dbus.BusObject, error) {
		return svc.OpenSession()
	})
	if err != nil {
		return "", keyringError(err)
	}
	defer runWithTimeout("close session", keyringOpTimeout, func() error {
		return svc.Close(session)
	})

	if err := runWithTimeout("unlock item", keyringPromptTimeout, func() error {
		return svc.Unlock(p)
	}); err != nil {
		return "", keyringError(err)
	}

	secret, err := callWithTimeout("get secret", keyringPromptTimeout, func() (*ss.Secret, error) {
		return svc.GetSecret(p, session.Path())
	})
	if err != nil {
		return "", keyringError(err)
	}
	return string(secret.Value), nil
}

// Delete removes the secret for service and account.
func (ssStore) Delete(service, account string) error {
	if service == "" || account == "" {
		return errors.New("service and account must not be empty")
	}

	svc, collection, err := keyringStore()
	if err != nil {
		return err
	}

	// Every item matching the pair is deleted — a credential is addressed by
	// service/account, so removing only one of several colliding copies would
	// leave the "deleted" secret readable through the survivor.
	paths, err := findItems(svc, collection, service, account)
	if err != nil {
		return err
	}
	var delErr error
	for _, p := range paths {
		if err := runWithTimeout("delete item", keyringPromptTimeout, func() error {
			return svc.Delete(p)
		}); err != nil {
			delErr = err
		}
	}
	return keyringError(delErr)
}

// List returns metadata for every item in the collection addressed by
// service/account attributes, regardless of which tool wrote it. Items lacking
// either attribute are skipped — nothing in the CLI can address them. If
// service is non-empty, only items for that service are returned.
func (ssStore) List(service string) ([]Item, error) {
	svc, collection, err := keyringStore()
	if err != nil {
		return nil, err
	}

	var paths []dbus.ObjectPath
	if service != "" {
		// Server-side search keeps filtered lists cheap — one round-trip
		// instead of a metadata fetch per collection item.
		paths, err = callWithTimeout("search items", keyringOpTimeout, func() ([]dbus.ObjectPath, error) {
			return svc.SearchItems(collection, map[string]string{"service": service})
		})
		if err != nil {
			return nil, keyringError(err)
		}
	} else {
		// Secret Service search requires at least one attribute, so enumerate
		// the collection's Items property and filter client-side.
		v, err := callWithTimeout("list items", keyringOpTimeout, func() (dbus.Variant, error) {
			return collection.GetProperty(collectionInterface + ".Items")
		})
		if err != nil {
			return nil, keyringError(err)
		}
		var ok bool
		paths, ok = v.Value().([]dbus.ObjectPath)
		if !ok {
			return nil, keyringError(fmt.Errorf("unexpected type for %s.Items: %T", collectionInterface, v.Value()))
		}
	}

	// Per-item metadata fetches dominate list latency on large collections
	// (one D-Bus round-trip each, serialized). Fetch them concurrently.
	items := make([]Item, 0, len(paths))
	var mu sync.Mutex
	var wg sync.WaitGroup
	var failures int
	sem := make(chan struct{}, 64)
	for _, p := range paths {
		wg.Add(1)
		go func(path dbus.ObjectPath) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			item, err := readItemMetadata(svc, path)
			if err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				return // locked or unreadable item; skip rather than fail the list
			}
			if item.Service == "" || item.Account == "" {
				return
			}
			mu.Lock()
			items = append(items, item)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	// A total failure means the daemon died mid-list or the connection is
	// broken — report that instead of masquerading as an empty keyring.
	if len(paths) > 0 && len(items) == 0 && failures > 0 {
		return nil, keyringError(fmt.Errorf("all %d item metadata reads failed", failures))
	}
	if failures > 0 {
		WriteLog("list: %d of %d items skipped (metadata read failed)", failures, len(paths))
	}

	// Concurrent fetch scrambles collection order; restore a stable one.
	sort.Slice(items, func(i, j int) bool {
		return statKey(items[i].Service, items[i].Account) < statKey(items[j].Service, items[j].Account)
	})
	return items, nil
}

// itemAttrTimeout bounds every per-item D-Bus call so a hung daemon stalls a
// single list for seconds, not forever — wg.Wait() would otherwise never
// return, wedging the panel refresh and the sequential MCP server loop.
const itemAttrTimeout = 10 * time.Second

// itemAttributes fetches just the Attributes property of an item.
func itemAttributes(svc *ss.SecretService, path dbus.ObjectPath) (map[string]string, error) {
	obj := svc.Object(secretServiceName, path)
	ctx, cancel := context.WithTimeout(context.Background(), itemAttrTimeout)
	defer cancel()
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, itemInterface, "Attributes").Store(&v); err != nil {
		return nil, err
	}
	attrs, _ := v.Value().(map[string]string)
	return attrs, nil
}

// readItemMetadata pulls all Item interface properties in one GetAll call —
// four round-trips per item would otherwise make large keyrings unusably slow.
func readItemMetadata(svc *ss.SecretService, path dbus.ObjectPath) (Item, error) {
	obj := svc.Object(secretServiceName, path)

	ctx, cancel := context.WithTimeout(context.Background(), itemAttrTimeout)
	defer cancel()
	var props map[string]dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, itemInterface).Store(&props); err != nil {
		return Item{}, keyringError(err)
	}

	attrs, _ := props["Attributes"].Value().(map[string]string)
	label, _ := props["Label"].Value().(string)

	var created, updated time.Time
	if c, ok := props["Created"].Value().(uint64); ok {
		created = time.Unix(int64(c), 0).UTC()
	}
	if m, ok := props["Modified"].Value().(uint64); ok {
		updated = time.Unix(int64(m), 0).UTC()
	}

	return Item{
		Service:   attrs["service"],
		Account:   attrs["account"],
		Label:     label,
		CreatedAt: created,
		UpdatedAt: updated,
		Owned:     attrs[appAttribute] == appAttributeVal,
	}, nil
}

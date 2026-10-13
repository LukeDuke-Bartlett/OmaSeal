package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

// nativeStore is the age-encrypted file backend (backend: native). Design
// and proven invariants: docs/design/native-store.md.
//
// Layout under $XDG_STATE_HOME/omaseal/native/:
//
//	identity.age  — X25519 private key, scrypt-passphrase-wrapped
//	identity.pub  — cleartext public recipient (not secret)
//	store.json    — {"items": {"svc/acct": {ct, created, updated}}}
//	store.lock    — flock target serializing writers
//
// Session identity (tmpfs, agentRuntimeDir()):
//
//	native-session.age  — identity re-wrapped to an ephemeral session key
//	native-session.json — {"key": "AGE-SECRET-…", "expires": unix} 0600
//
// The asymmetric property: Set/Delete/List encrypt to the public recipient
// and never consult key material, so they work while locked and a failed
// unlock is a failed read — never a write (the Sept-30 re-key class,
// eliminated by construction).
type nativeStore struct {
	dir         string                             // state dir for the store files
	runtimeDir  string                             // tmpfs dir for session identity
	pub         *age.X25519Recipient               // always available — public half
	identity    *age.X25519Identity                // nil while locked
	identityEnc []byte                             // passphrase-wrapped identity blob
	prompt      func(label string) (string, error) // nil → never prompt
	now         func() time.Time
	sessionTTL  time.Duration
}

var _ Store = (*nativeStore)(nil)

// nativeDoc is the on-disk store.json shape.
type nativeDoc struct {
	Items map[string]nativeItem `json:"items"`
}

type nativeItem struct {
	CT      string `json:"ct"`
	Created int64  `json:"created"`
	Updated int64  `json:"updated"`
	// External marks provenance: true means the item originated outside
	// OmaSeal (carried over a migration); false/zero means OmaSeal wrote it.
	// Inverted on purpose: records predating this field unmarshal as
	// External=false → Owned=true, the correct default while only omaseal
	// writes the native store.
	External bool `json:"external,omitempty"`
}

// nativeEnvelope binds the plaintext to its name — a ciphertext moved under
// a different service/account fails the check after decrypt (ErrTamper).
type nativeEnvelope struct {
	Svc   string `json:"s"`
	Acct  string `json:"a"`
	Value string `json:"v"`
}

// nativeSession is the runtime-dir sidecar for the session-wrapped identity.
type nativeSession struct {
	Key     string `json:"key"`
	Expires int64  `json:"expires"`
}

var (
	errNativeLocked = errors.New("store locked")
	errNativeTamper = errors.New("value not bound to this name")
	errItemExists   = errors.New("item already present")
)

// nativeKey is the store.json key for a credential. Each half is percent-
// escaped (%25 → %, %2F → /) so a '/' or '%' in a foreign SS attribute can
// neither collide with the separator nor forge another item's key — URL-keyed
// services (https://…) are a real credential-manager convention. Paired with
// the strings.Cut + unescKeyPart split in List.
func nativeKey(service, account string) string {
	return escKeyPart(service) + "/" + escKeyPart(account)
}

func escKeyPart(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	return strings.ReplaceAll(s, "/", "%2F")
}

// unescKeyPart reverses escKeyPart; unknown %-sequences pass through
// untouched so keys written before escaping shipped (plain svc/acct) still
// read correctly.
func unescKeyPart(s string) string {
	s = strings.ReplaceAll(s, "%2F", "/")
	return strings.ReplaceAll(s, "%25", "%")
}

const (
	nativeIdentityFile = "identity.age"
	nativePubFile      = "identity.pub"
	nativeStoreFile    = "store.json"
	nativeLockFile     = "store.lock"
	nativeSessAgeFile  = "native-session.age"
	nativeSessJSONFile = "native-session.json"
	defaultNativeTTL   = 15 * time.Minute
)

// newNativeStore returns the production native backend rooted at
// $XDG_STATE_HOME/omaseal/native with the agent runtime dir for sessions.
func newNativeStore() *nativeStore {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".local", "state")
		}
	}
	return newNativeStoreAt(filepath.Join(base, "omaseal", "native"), agentRuntimeDir())
}

// newNativeStoreAt is the testable constructor — dirs and prompt injected.
func newNativeStoreAt(dir, runtimeDir string) *nativeStore {
	return &nativeStore{
		dir:        dir,
		runtimeDir: runtimeDir,
		prompt:     nativePassphrasePromptTTY,
		now:        func() time.Time { return time.Now().UTC() },
		sessionTTL: defaultNativeTTL,
	}
}

// --- Store interface -----------------------------------------------------

// Set encrypts value to the public recipient — works while locked.
func (s *nativeStore) Set(service, account, secret string) error {
	return s.set(service, account, secret, true, false)
}

// migrateSet is Set with carried provenance — used by `omaseal migrate` so an
// item written by another tool keeps its external flag in the native store.
// Set-if-absent under the flock: a concurrent Set landing between the
// migrate presence check and this write must not be overwritten (errItemExists).
func (s *nativeStore) migrateSet(service, account, secret string, owned bool) error {
	return s.set(service, account, secret, owned, true)
}

func (s *nativeStore) set(service, account, secret string, owned, ifAbsent bool) error {
	if service == "" || account == "" || secret == "" {
		return errors.New("service, account, and secret must not be empty")
	}
	if err := s.ensureInit(); err != nil {
		return err
	}
	env, _ := json.Marshal(nativeEnvelope{Svc: service, Acct: account, Value: secret})
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.pub)
	if err != nil {
		return keyringError(err)
	}
	if _, err := w.Write(env); err != nil {
		return keyringError(err)
	}
	if err := w.Close(); err != nil {
		return keyringError(err)
	}
	key := nativeKey(service, account)
	var existed bool
	err = s.update(func(d *nativeDoc) {
		if _, ok := d.Items[key]; ok && ifAbsent {
			existed = true
			return
		}
		it, ok := d.Items[key]
		if !ok {
			it.Created = s.now().Unix()
		}
		it.CT = base64.StdEncoding.EncodeToString(buf.Bytes())
		it.Updated = s.now().Unix()
		it.External = !owned
		d.Items[key] = it
	})
	if existed {
		return errItemExists
	}
	return err
}

// Get decrypts the value bound to service/account — needs the identity.
func (s *nativeStore) Get(service, account string) (string, error) {
	if service == "" || account == "" {
		return "", errors.New("service and account must not be empty")
	}
	if err := s.ensureInit(); err != nil {
		return "", err
	}
	d, err := s.read()
	if err != nil {
		return "", err
	}
	it, ok := d.Items[nativeKey(service, account)]
	if !ok {
		return "", newError("not_found", "omaseal set", keyring.ErrNotFound)
	}
	if err := s.ensureIdentity(); err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(it.CT)
	if err != nil {
		return "", keyringError(err)
	}
	src, err := age.Decrypt(bytes.NewReader(raw), s.identity)
	if err != nil {
		return "", keyringError(fmt.Errorf("decrypt: %w", err))
	}
	plain, err := io.ReadAll(src)
	if err != nil {
		return "", keyringError(err)
	}
	var env nativeEnvelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return "", keyringError(err)
	}
	if env.Svc != service || env.Acct != account {
		return "", newError("tamper", "store integrity check failed — see omaseal doctor", errNativeTamper)
	}
	return env.Value, nil
}

// Delete removes the item under the write lock — works while locked.
func (s *nativeStore) Delete(service, account string) error {
	if service == "" || account == "" {
		return errors.New("service and account must not be empty")
	}
	if err := s.ensureInit(); err != nil {
		return err
	}
	key := nativeKey(service, account)
	var found bool
	err := s.update(func(d *nativeDoc) {
		if _, ok := d.Items[key]; ok {
			found = true
			delete(d.Items, key)
		}
	})
	if err != nil {
		return err
	}
	if !found {
		return newError("not_found", "omaseal list", keyring.ErrNotFound)
	}
	return nil
}

// List returns cleartext names + timestamps — names are the exposure either
// way (store.json is on disk), so no unlock is required; matches the design
// doc and keeps the panel cheap.
func (s *nativeStore) List(service string) ([]Item, error) {
	if err := s.ensureInit(); err != nil {
		return nil, err
	}
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(d.Items))
	for k, it := range d.Items {
		rawSvc, rawAcct, ok := strings.Cut(k, "/")
		if !ok || rawSvc == "" || rawAcct == "" {
			continue
		}
		svc, acct := unescKeyPart(rawSvc), unescKeyPart(rawAcct)
		if service != "" && svc != service {
			continue
		}
		items = append(items, Item{
			Service:   svc,
			Account:   acct,
			Label:     fmt.Sprintf("OmaSeal: %s / %s", svc, acct),
			CreatedAt: time.Unix(it.Created, 0).UTC(),
			UpdatedAt: time.Unix(it.Updated, 0).UTC(),
			Owned:     !it.External,
		})
	}
	return items, nil
}

// --- Unlock / session identity ---------------------------------------------

// unlockIdentity verifies a passphrase against identity.age and, on success,
// holds the identity in memory and seeds the tmpfs session files expiring at
// expires. A wrong passphrase is a failed read — nothing on disk is touched
// (invariant I2).
func (s *nativeStore) unlockIdentity(passphrase string, expires time.Time) error {
	if s.identityEnc == nil {
		blob, err := os.ReadFile(filepath.Join(s.dir, nativeIdentityFile))
		if errors.Is(err, os.ErrNotExist) {
			return newError("store_uninitialized", "omaseal get (or migrate) in a terminal first", err)
		}
		if err != nil {
			return keyringError(err)
		}
		s.identityEnc = blob
	}
	sid, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return keyringError(err)
	}
	src, err := age.Decrypt(bytes.NewReader(s.identityEnc), sid)
	if err != nil {
		return newError("unlock_denied", "wrong passphrase", fmt.Errorf("unlock: %w", err))
	}
	raw, err := io.ReadAll(src)
	if err != nil {
		return keyringError(err)
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
	if err != nil {
		return keyringError(err)
	}
	s.identity = id
	return s.seedSession(expires)
}

// ensureIdentity resolves the decryption identity: memory → tmpfs session →
// TTY prompt → locked error. Never prompts for agents/non-TTY callers.
func (s *nativeStore) ensureIdentity() error {
	if s.identity != nil {
		return nil
	}
	if err := s.loadSession(); err == nil {
		return nil
	}
	if s.prompt != nil {
		pass, err := s.prompt("OmaSeal passphrase")
		if err == nil && pass != "" {
			if uerr := s.unlockIdentity(pass, s.now().Add(s.sessionTTL)); uerr == nil {
				return nil
			} else {
				return uerr
			}
		}
	}
	return newError("locked", "omaseal agent unlock (or run omaseal get in a terminal)", errNativeLocked)
}

// seedSession re-wraps the in-memory identity to an ephemeral key in the
// runtime dir — tmpfs, 0600, dies at logout like the agent session file.
func (s *nativeStore) seedSession(expires time.Time) error {
	if s.identity == nil {
		return errNativeLocked
	}
	eph, err := age.GenerateX25519Identity()
	if err != nil {
		return keyringError(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, eph.Recipient())
	if err != nil {
		return keyringError(err)
	}
	if _, err := w.Write([]byte(s.identity.String())); err != nil {
		return keyringError(err)
	}
	if err := w.Close(); err != nil {
		return keyringError(err)
	}
	sess := nativeSession{
		Key:     eph.String(),
		Expires: expires.Unix(),
	}
	raw, err := json.Marshal(sess)
	if err != nil {
		return keyringError(err)
	}
	if err := os.MkdirAll(s.runtimeDir, 0700); err != nil {
		return keyringError(err)
	}
	if err := atomicWriteFile(filepath.Join(s.runtimeDir, nativeSessJSONFile), raw, 0600); err != nil {
		return keyringError(err)
	}
	return atomicWriteFile(filepath.Join(s.runtimeDir, nativeSessAgeFile), buf.Bytes(), 0600)
}

// loadSession unwraps the tmpfs session identity if present and unexpired.
// An expired session is unlinked — key material must not outlive its
// window. Corrupt sessions are left in place: seedSession writes the
// .json/.age pair as two atomic renames, so a torn pair is a mid-write
// window a concurrent reader must not mistake for dead files.
func (s *nativeStore) loadSession() error {
	raw, err := os.ReadFile(filepath.Join(s.runtimeDir, nativeSessJSONFile))
	if err != nil {
		return err
	}
	var sess nativeSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return err
	}
	if s.now().Unix() > sess.Expires {
		if rerr := s.unlinkSessionFiles(); rerr != nil {
			return fmt.Errorf("session expired (cleanup failed: %w)", rerr)
		}
		return errNativeLocked
	}
	sid, err := age.ParseX25519Identity(sess.Key)
	if err != nil {
		return err
	}
	enc, err := os.ReadFile(filepath.Join(s.runtimeDir, nativeSessAgeFile))
	if err != nil {
		return err
	}
	src, err := age.Decrypt(bytes.NewReader(enc), sid)
	if err != nil {
		return err
	}
	plain, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(plain)))
	if err != nil {
		return err
	}
	s.identity = id
	return nil
}

// unlinkSessionFiles removes the tmpfs session pair, reporting removal
// failures so callers cannot mistake retained key material for scrubbed
// material. Missing files are not errors.
func (s *nativeStore) unlinkSessionFiles() error {
	return errors.Join(
		removeIfExists(filepath.Join(s.runtimeDir, nativeSessJSONFile)),
		removeIfExists(filepath.Join(s.runtimeDir, nativeSessAgeFile)),
	)
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// clearNativeSession removes the tmpfs session identity — called by
// `agent lock` so locking the agent also drops the unwrapped key path.
func (s *nativeStore) clearNativeSession() error {
	s.identity = nil
	return s.unlinkSessionFiles()
}

// --- init / file layer -----------------------------------------------------

// ensureInit loads the wrapped identity + public recipient, lazily creating
// them on a TTY first run. Non-TTY with no identity fails with a hint —
// agents never conjure the store.
func (s *nativeStore) ensureInit() error {
	if s.pub != nil {
		return nil
	}
	idPath := filepath.Join(s.dir, nativeIdentityFile)
	blob, err := os.ReadFile(idPath)
	if errors.Is(err, os.ErrNotExist) {
		return s.initFresh()
	}
	if err != nil {
		return keyringError(err)
	}
	s.identityEnc = blob
	if err := s.loadPub(); err != nil {
		// identity.age exists but identity.pub is missing/corrupt — a
		// torn init. Self-heal: unwrap the identity (prompt on TTY) and
		// rewrite the pub file from it, rather than wedging the store.
		return s.healPub()
	}
	return nil
}

// healPub recovers a torn init: unlock the identity, then derive and write
// the public recipient file. Needs the passphrase → prompt path only.
func (s *nativeStore) healPub() error {
	if err := s.ensureIdentity(); err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(s.dir, nativePubFile),
		[]byte(s.identity.Recipient().String()+"\n"), 0600); err != nil {
		return keyringError(err)
	}
	s.pub = s.identity.Recipient()
	return nil
}

// initFresh creates a new identity — the ONLY path that writes a passphrase-
// wrapped file. Needs a TTY (or an injected prompt); two prompts to confirm.
// The whole init runs under the store flock: two racing first-writers must
// not interleave the identity.age/identity.pub pair — a mismatched pair
// encrypts to a key nobody can unwrap (silent, permanent loss). A crash
// mid-pair is still possible and is covered by healPub.
func (s *nativeStore) initFresh() error {
	if s.prompt == nil {
		return newError("store_uninitialized",
			"run `omaseal get` once in a terminal to initialize the native store",
			errors.New("no identity at "+filepath.Join(s.dir, nativeIdentityFile)))
	}
	// First-init prompts stay TTY-only — fail before touching the
	// filesystem so a non-TTY first-touch leaves no stray dir+lock.
	if !stdinIsTTY() {
		return newError("store_uninitialized",
			"run `omaseal get` once in a terminal to initialize the native store",
			errors.New("no tty"))
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return keyringError(err)
	}
	lp := filepath.Join(s.dir, nativeLockFile)
	lf, err := os.OpenFile(lp, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return keyringError(err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return keyringError(err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	// Re-check inside the lock — a racing process may have completed init
	// while we waited; adopt its identity, never overwrite. A torn pair
	// (identity present, pub missing/corrupt) heals through unlock.
	blob, err := os.ReadFile(filepath.Join(s.dir, nativeIdentityFile))
	if err == nil {
		s.identityEnc = blob
		if perr := s.loadPub(); perr != nil {
			return s.healPub()
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return keyringError(err)
	}

	pass, err := s.prompt("New OmaSeal passphrase (creates the native store)")
	if err != nil || pass == "" {
		return newError("store_uninitialized", "passphrase required", errors.New("init aborted"))
	}
	confirm, err := s.prompt("Confirm passphrase")
	if err != nil || confirm != pass {
		return newError("store_uninitialized", "passphrases did not match", errors.New("init aborted"))
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return keyringError(err)
	}
	wrapped, err := wrapNativeIdentity(id, pass)
	if err != nil {
		return keyringError(err)
	}
	if err := atomicWriteFile(filepath.Join(s.dir, nativeIdentityFile), wrapped, 0600); err != nil {
		return keyringError(err)
	}
	if err := atomicWriteFile(filepath.Join(s.dir, nativePubFile),
		[]byte(id.Recipient().String()+"\n"), 0600); err != nil {
		return keyringError(err)
	}
	s.identity = id
	s.identityEnc = wrapped
	s.pub = id.Recipient()
	return s.seedSession(s.now().Add(s.sessionTTL))
}

func (s *nativeStore) loadPub() error {
	pb, err := os.ReadFile(filepath.Join(s.dir, nativePubFile))
	if err != nil {
		return keyringError(err)
	}
	r, err := age.ParseX25519Recipient(strings.TrimSpace(string(pb)))
	if err != nil {
		return keyringError(err)
	}
	s.pub = r
	return nil
}

// update serializes read-modify-write of store.json under flock — the
// audit-chain lesson: re-read inside the lock, never before.
func (s *nativeStore) update(fn func(*nativeDoc)) error {
	lp := filepath.Join(s.dir, nativeLockFile)
	lf, err := os.OpenFile(lp, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return keyringError(err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return keyringError(err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	d, err := s.read()
	if err != nil {
		return err
	}
	fn(&d)
	raw, err := json.Marshal(d)
	if err != nil {
		return keyringError(err)
	}
	return atomicWriteFile(filepath.Join(s.dir, nativeStoreFile), raw, 0600)
}

func (s *nativeStore) read() (nativeDoc, error) {
	d := nativeDoc{Items: map[string]nativeItem{}}
	raw, err := os.ReadFile(filepath.Join(s.dir, nativeStoreFile))
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, keyringError(err)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &d); err != nil {
			return d, keyringError(err)
		}
	}
	if d.Items == nil {
		d.Items = map[string]nativeItem{}
	}
	return d, nil
}

func wrapNativeIdentity(id *age.X25519Identity, passphrase string) ([]byte, error) {
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte(id.String())); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// atomicWriteFile is temp + fsync + rename — a crash leaves the prior
// coherent file, never a partial one.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if f, err := os.OpenFile(tmp, os.O_RDWR, 0); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return os.Rename(tmp, path)
}

// nativePromptGUI is the masked-graphical-prompt seam for the store
// passphrase — tests stub it; real builds bind guiPromptDesc.
var nativePromptGUI = guiPromptDesc

// nativePassphrasePromptTTY reads the store passphrase on the TTY only.
// ensureIdentity binds this via s.prompt, preserving the invariant that
// implicit unlock-on-read never prompts non-TTY callers (agents, the panel's
// background `omaseal list`, pipes) — they take the locked path instead of a
// spontaneous dialog.
func nativePassphrasePromptTTY(label string) (string, error) {
	if !stdinIsTTY() {
		return "", errors.New("no tty")
	}
	fmt.Fprintf(os.Stderr, "%s: ", label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // ReadPassword does not echo the newline
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// nativePassphrasePrompt serves explicit user-driven unlock: the TTY when one
// exists, else a masked GUI prompt (pinentry or zenity) in a graphical
// session — that's what `agent unlock` invoked from a panel or launcher gets.
// Truly headless callers get "no tty" and take the locked path.
func nativePassphrasePrompt(label string) (string, error) {
	if stdinIsTTY() {
		return nativePassphrasePromptTTY(label)
	}
	if graphicalSession() {
		ctx, cancel := withPromptDeadline(context.Background())
		defer cancel()
		return nativePromptGUI(ctx, label+" (requested by "+requesterName()+")")
	}
	return "", errors.New("no tty")
}

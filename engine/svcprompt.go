package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
)

// Prompt lifecycle (KTD2): only Unlock/Lock/Delete/CreateItem can mint a
// Prompt — reads (GetSecrets/GetSecret) return IsLocked instead. A minted
// Prompt object lives at /prompt/<id>; the owner calls Prompt() to run the
// GUI prompter; exactly one Completed signal fires per prompt, always.
//
// Prompt-derived unlocks hold identity in memory only — they never write
// native-session files. Instead a non-secret `unlock-epoch` marker lands in
// the runtime dir so `omaseal agent lock` (or Service.Lock, or the TTL) can
// revoke a daemon-only unlock: all three paths unlink the marker, and the
// daemon drops identity when the marker is gone.

const svcUnlockEpochFile = "unlock-epoch"
const svcMaxPromptsGlobal = 256

// svcPrompt is one in-flight Prompt object.
type svcPrompt struct {
	owner   string // unique name that may Prompt()/Dismiss()
	uid     uint32
	running bool
	cancel  context.CancelFunc // non-nil while the op is in flight
	op      func(ctx context.Context) ([]dbus.ObjectPath, error)
	objects []dbus.ObjectPath // unlocked paths echoed back via Completed
}

func svcUnlockEpochPath() string {
	return filepath.Join(agentRuntimeDir(), svcUnlockEpochFile)
}

// svcAgentModeLocked reads the policy file per call — a panic-control
// setting must not go stale inside a long-lived daemon.
func svcAgentModeLocked() bool {
	p, err := loadAgentPolicy()
	return err == nil && p.Mode == "lock"
}

// mintPrompt registers a Prompt object and returns its path. One active
// prompt per sender — a second mint from the same client reuses it.
// objects is what Completed echoes on success (the paths the caller asked
// to have unlocked); op runs off-mutex with a cancel wired to Dismiss.
func (d *svcDaemon) mintPrompt(sender, exe string, objects []dbus.ObjectPath, op func(context.Context) ([]dbus.ObjectPath, error)) (dbus.ObjectPath, *dbus.Error) {
	// Peer uid resolution is a bus round-trip — do it BEFORE taking mu so a
	// slow bus can't serialize the daemon behind one lookup.
	uid, _ := svcPeerUID(d.conn, sender)

	d.mu.Lock()
	defer d.mu.Unlock()
	for path, p := range d.prompts {
		if p.owner == sender {
			return path, nil // dedup
		}
	}
	// A refused mint is an error, not "/" — to a client, "/" reads as
	// "unlocked nothing, no prompt needed", which hides the refusal.
	if len(d.prompts) >= svcMaxPromptsGlobal {
		return "", svcErrAccessDenied("prompt budget exhausted")
	}
	if d.promptsForUIDLocked(uid) >= svcMaxPromptsPerUID {
		return "", svcErrAccessDenied("per-uid prompt budget exhausted")
	}
	path := dbus.ObjectPath(string(svcBasePath) + "/prompt/" + svcRandID())
	d.prompts[path] = &svcPrompt{owner: sender, uid: uid, op: op, objects: objects}
	WriteLog("provider: mint prompt %s sender=%s exe=%s", path, sender, exe)
	return path, nil
}

// promptsForUIDLocked counts prompts owned by one uid. A failed uid lookup
// lands callers in the uid==0 bucket — capped like any other, never a
// silent count-all.
func (d *svcDaemon) promptsForUIDLocked(uid uint32) int {
	n := 0
	for _, p := range d.prompts {
		if p.uid == uid {
			n++
		}
	}
	return n
}

// drivePrompt runs the prompt's operation off-mutex, then emits Completed
// and sweeps the object. A second Prompt() on a running path is a no-op.
func (d *svcDaemon) drivePrompt(path dbus.ObjectPath, sender string) *dbus.Error {
	d.mu.Lock()
	p, ok := d.prompts[path]
	if !ok {
		d.mu.Unlock()
		return svcErrNoSuchObject(string(path))
	}
	if p.owner != sender {
		d.mu.Unlock()
		return svcErrAccessDenied("prompt owned by another client")
	}
	if p.running {
		d.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.running = true
	p.cancel = cancel
	op := p.op
	d.mu.Unlock()

	go func() {
		var unlocked []dbus.ObjectPath
		var err error
		if op != nil {
			unlocked, err = op(ctx)
		}
		d.finishPrompt(path, false, unlocked, err)
	}()
	return nil
}

// dismissPrompt cancels the prompt — the in-flight op's context dies so a
// deferred unlock can still be vetoed — and Completed fires dismissed.
func (d *svcDaemon) dismissPrompt(path dbus.ObjectPath, sender string) *dbus.Error {
	d.mu.Lock()
	p, ok := d.prompts[path]
	if !ok {
		d.mu.Unlock()
		return svcErrNoSuchObject(string(path))
	}
	if p.owner != sender {
		d.mu.Unlock()
		return svcErrAccessDenied("prompt owned by another client")
	}
	cancel := p.cancel
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	d.finishPrompt(path, true, nil, context.Canceled)
	return nil
}

// finishPrompt emits Completed exactly once and removes the object.
// Per spec the result variant echoes the object paths the prompt unlocked —
// libsecret branches on the array, not the error text.
func (d *svcDaemon) finishPrompt(path dbus.ObjectPath, dismissed bool, unlocked []dbus.ObjectPath, opErr error) {
	d.mu.Lock()
	p, ok := d.prompts[path]
	if !ok {
		d.mu.Unlock()
		return
	}
	delete(d.prompts, path)
	objects := p.objects
	d.mu.Unlock()

	if opErr != nil {
		WriteLog("provider: prompt %s failed: %v", path, opErr)
	}
	var result dbus.Variant
	switch {
	case dismissed || opErr != nil:
		result = dbus.MakeVariant([]dbus.ObjectPath{})
	case unlocked != nil:
		result = dbus.MakeVariant(unlocked)
	default:
		result = dbus.MakeVariant(objects)
	}
	_ = d.conn.Emit(path, "org.freedesktop.Secret.Prompt.Completed", dismissed || opErr != nil, result)
}

// unlockViaPrompt runs the GUI passphrase prompt (caller exe attributed in
// the description) and, on success, holds the identity in memory only —
// plus the unlock-epoch marker that lets `agent lock` revoke it later.
// The passphrase/unwrap work happens OFF d.mu; only the state commit locks.
// A cancelled context vetoes the commit — Dismiss mid-prompt must not
// leave the vault armed.
func (d *svcDaemon) unlockViaPrompt(ctx context.Context, exe string) error {
	pctx, cancel := withPromptDeadline(ctx)
	defer cancel()
	pass, err := guiPromptDesc(pctx, "Unlock the OmaSeal vault (requested by "+exe+")")
	if err != nil {
		return err
	}
	if pass == "" {
		return fmt.Errorf("empty passphrase")
	}
	// scrypt unwrap is the ~500ms path — keep it off the daemon mutex. The
	// identity is NOT published here: an in-flight unwrap completing after
	// Service.Lock or Dismiss must not arm the vault behind its back, so
	// the store happens only under mu after the cancellation check.
	id, err := d.store.unwrapIdentityPass(pass)
	if err != nil {
		return err
	}
	expiry := d.now().Add(defaultNativeTTL)
	if p, perr := loadAgentPolicy(); perr == nil && p.SessionMinutes > 0 {
		expiry = d.now().Add(time.Duration(p.SessionMinutes) * time.Minute)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if ctx.Err() != nil {
		// Dismissed or locked while the prompter was open — the passphrase
		// succeeded but the identity was never published.
		return ctx.Err()
	}
	d.store.identity.Store(id)
	d.promptIdentity = true
	d.promptExpiry = expiry
	if werr := writeFileMode(svcUnlockEpochPath(), []byte(fmt.Sprintf("%d", expiry.Unix())), 0600); werr != nil {
		d.promptIdentity = false
		d.store.identity.Store(nil)
		return fmt.Errorf("unlock-epoch marker: %w", werr)
	}
	WriteLog("provider: vault unlocked via prompt (memory only, expiry %s)", expiry.Format(time.RFC3339))
	return nil
}

// lockDaemon drops the in-memory identity, the marker, AND the native CLI
// session files — Service.Lock must leave the vault actually locked, or a
// still-live `omaseal agent unlock` session would be silently re-adopted on
// the next call and the Lock return value would lie.
func (d *svcDaemon) lockDaemon() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lockDaemonLocked()
}

// lockDaemonLocked is lockDaemon under mu. Per the plan: a real Lock unlinks
// the session files so nothing re-adopts a file-derived identity. In-flight
// prompt ops are cancelled first — otherwise their commit section can
// re-publish the identity after this clear.
func (d *svcDaemon) lockDaemonLocked() {
	for _, p := range d.prompts {
		if p.cancel != nil {
			p.cancel()
		}
	}
	d.store.identity.Store(nil)
	d.promptIdentity = false
	if err := d.store.unlinkSessionFiles(); err != nil {
		WriteLog("provider: native session unlink: %v", err)
	}
	if err := os.Remove(svcUnlockEpochPath()); err != nil && !os.IsNotExist(err) {
		WriteLog("provider: unlock-epoch marker remove: %v", err)
	}
	d.emitPropsChanged(svcCollectionPath(), "org.freedesktop.Secret.Collection",
		map[string]dbus.Variant{"Locked": dbus.MakeVariant(true)})
	WriteLog("provider: vault locked")
}

// checkPromptIdentity enforces the prompt-derived lifecycle: TTL expiry and
// external marker removal (agent lock) both relock. Called from lockedLocked
// under mu; does no prompting, just stat+time checks.
func (d *svcDaemon) checkPromptIdentity() {
	if !d.promptIdentity || d.store.identity.Load() == nil {
		return
	}
	if d.now().After(d.promptExpiry) {
		WriteLog("provider: prompt-derived unlock expired")
		d.lockDaemonLocked()
		return
	}
	if _, err := os.Stat(svcUnlockEpochPath()); err != nil {
		WriteLog("provider: unlock-epoch marker gone — relocking")
		d.lockDaemonLocked()
	}
}

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

// The Secret Service method surface. Signatures follow the draft spec;
// libsecret/go-keyring call these verbatim. Every method checks its path
// class (KTD3) and resolves the sender to uid/pid/exe for the audit line.
//
// Secret wire type (oayays): session path, params, value, content-type.

// svcSecret is the (oayays) wire struct.
type svcSecret struct {
	Session     dbus.ObjectPath
	Params      []byte
	Value       []byte
	ContentType string
}

// svcGuard converts a handler panic into a wire error instead of a daemon
// crash — godbus runs each call in a goroutine with no recover, so any
// panic kills the process. Defer this in every exported method.
func svcGuard(err **dbus.Error) {
	if r := recover(); r != nil {
		WriteLog("provider: handler panic: %v", r)
		*err = svcErrFailed("internal error")
	}
}

// svcGate checks the per-call sender policy: same-uid + agent-mode check.
// Returns the caller's attribution triple or a wire error.
func (d *svcDaemon) svcGate(msg dbus.Message) (uid, pid uint32, exe string, err *dbus.Error) {
	sender := svcMsgSender(msg)
	if sender == "" {
		return 0, 0, "", svcErrAccessDenied("no sender")
	}
	uid, pid, exe, terr := svcPeerInfo(d.conn, sender)
	if terr != nil {
		return 0, 0, "", svcErrAccessDenied("peer credentials unavailable")
	}
	if uid != uint32(os.Getuid()) {
		return 0, 0, "", svcErrAccessDenied(fmt.Sprintf("uid %d != %d", uid, os.Getuid()))
	}
	if svcAgentModeLocked() {
		return 0, 0, "", svcErrAccessDenied("agent mode is locked")
	}
	return uid, pid, exe, nil
}

// --- Service -------------------------------------------------------------

func (s svcServiceAPI) OpenSession(msg dbus.Message, algorithm string, input dbus.Variant) (out dbus.Variant, sessionPath dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassService {
		return dbus.Variant{}, "/", svcErrUnknownObject("OpenSession on non-service path")
	}
	uid, pid, exe, err := s.d.svcGate(msg)
	if err != nil {
		return dbus.Variant{}, "/", err
	}
	sender := svcMsgSender(msg)

	var codec svcSessionCodec
	switch algorithm {
	case svcAlgPlain:
		codec = svcPlainCodec{}
		out = input // spec: output echoes the input variant
	case svcAlgDH:
		peerPub, ok := input.Value().([]byte)
		if !ok || len(peerPub) == 0 {
			return dbus.Variant{}, "/", svcErrInvalidArgs("dh input must be ay peer pubkey")
		}
		priv, pub, kerr := svcNewDHKeypair()
		if kerr != nil {
			return dbus.Variant{}, "/", svcErrFailed(kerr.Error())
		}
		codec, kerr = svcNewDHCodec(priv, peerPub)
		if kerr != nil {
			return dbus.Variant{}, "/", svcErrInvalidArgs(kerr.Error())
		}
		out = dbus.MakeVariant(pub)
	default:
		return dbus.Variant{}, "/", svcErrNotSupported("algorithm " + algorithm)
	}

	s.d.mu.Lock()
	if s.d.countSessionsForUIDLocked(uid) >= svcMaxSessionsPerUID {
		s.d.mu.Unlock()
		return dbus.Variant{}, "/", svcErrAccessDenied("session budget exhausted")
	}
	path := dbus.ObjectPath(string(svcBasePath) + "/session/" + svcRandID())
	s.d.sessions[path] = &svcSession{owner: sender, uid: uid, codec: codec, created: s.d.now()}
	s.d.mu.Unlock()

	WriteLog("provider: opensession alg=%s sender=%s pid=%d exe=%s", algorithm, sender, pid, exe)
	return out, path, nil
}

func (s svcServiceAPI) CreateCollection(msg dbus.Message, _ map[string]dbus.Variant, _ string) (coll dbus.ObjectPath, prompt dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	// v1 serves one fixed collection — R-scoped deferral.
	return "/", "/", svcErrNotSupported("single fixed collection")
}

func (s svcServiceAPI) SearchItems(msg dbus.Message, attrs map[string]string) (unlocked []dbus.ObjectPath, locked []dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassService {
		return nil, nil, svcErrUnknownObject("SearchItems on non-service path")
	}
	if _, _, _, err := s.d.svcGate(msg); err != nil {
		return nil, nil, err
	}
	found := s.d.searchItems(attrs)
	if s.d.locked() {
		return nil, found, nil // locked list — never empty for a locked vault
	}
	return found, nil, nil
}

func (s svcServiceAPI) Unlock(msg dbus.Message, objects []dbus.ObjectPath) (unlocked []dbus.ObjectPath, prompt dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassService {
		return nil, "/", svcErrUnknownObject("Unlock on non-service path")
	}
	_, _, exe, err := s.d.svcGate(msg)
	if err != nil {
		return nil, "/", err
	}
	// Everything asked for resolves to the one collection — reject foreign
	// paths so a caller learns rather than silently no-ops.
	for _, o := range objects {
		if c := svcClassify(o); c != svcClassCollection && c != svcClassItem && c != svcClassService {
			return nil, "/", svcErrNoSuchObject(string(o))
		}
	}
	resolved := s.d.resolvableObjects(objects)
	if !s.d.locked() {
		return resolved, "/", nil
	}
	sender := svcMsgSender(msg)
	prompt, derr = s.d.mintPrompt(sender, exe, resolved, func(ctx context.Context) ([]dbus.ObjectPath, error) {
		if err := s.d.unlockViaPrompt(ctx, exe); err != nil {
			return nil, err
		}
		// Re-resolve after unlock: a path could have been deleted while the
		// prompt was up, and echoing it back would lie to state-tracking
		// clients.
		return s.d.resolvableObjects(objects), nil
	})
	if derr != nil {
		return nil, "/", derr
	}
	return nil, prompt, nil
}

// resolvableObjects filters requested paths to what actually exists —
// service/collection by class, items only if they're in the index. Echoing
// unresolvable paths back as "unlocked" lies to clients tracking state.
func (d *svcDaemon) resolvableObjects(objects []dbus.ObjectPath) []dbus.ObjectPath {
	var out []dbus.ObjectPath
	for _, o := range objects {
		switch svcClassify(o) {
		case svcClassCollection, svcClassService:
			out = append(out, o)
		case svcClassItem:
			if it, err := d.itemAt(o); err == nil && it != nil {
				out = append(out, o)
			}
		}
	}
	return out
}

func (s svcServiceAPI) Lock(msg dbus.Message, objects []dbus.ObjectPath) (locked []dbus.ObjectPath, prompt dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassService {
		return nil, "/", svcErrUnknownObject("Lock on non-service path")
	}
	if _, _, _, err := s.d.svcGate(msg); err != nil {
		return nil, "/", err
	}
	s.d.lockDaemon()
	return objects, "/", nil
}

func (s svcServiceAPI) GetSecrets(msg dbus.Message, items []dbus.ObjectPath, sessionPath dbus.ObjectPath) (secrets map[dbus.ObjectPath]svcSecret, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassService {
		return nil, svcErrUnknownObject("GetSecrets on non-service path")
	}
	if _, _, _, err := s.d.svcGate(msg); err != nil {
		return nil, err
	}
	sess, err := s.d.sessionFor(msg, sessionPath)
	if err != nil {
		return nil, err
	}
	if s.d.locked() {
		return nil, svcErrIsLocked()
	}
	out := map[dbus.ObjectPath]svcSecret{}
	for _, itemPath := range items {
		it, ierr := s.d.itemAt(itemPath)
		if ierr != nil {
			return nil, ierr
		}
		svc, acct, ok := svcSplitKey(it.Key)
		if !ok {
			return nil, svcErrFailed("bad index key " + it.Key)
		}
		plain, gerr := s.d.store.Get(svc, acct)
		if gerr != nil {
			return nil, svcErrFrom(gerr)
		}
		params, value, cerr := sess.codec.encrypt([]byte(plain))
		if cerr != nil {
			return nil, svcErrFailed(cerr.Error())
		}
		out[itemPath] = svcSecret{Session: sessionPath, Params: params, Value: value, ContentType: "text/plain"}
	}
	WriteLog("provider: getsecrets n=%d sender=%s", len(items), svcMsgSender(msg))
	return out, nil
}

func (s svcServiceAPI) ReadAlias(msg dbus.Message, name string) (coll dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassService {
		return "/", svcErrUnknownObject("ReadAlias on non-service path")
	}
	if _, _, _, err := s.d.svcGate(msg); err != nil {
		return "/", err
	}
	if name == "default" {
		return svcCollectionPath(), nil
	}
	return "/", nil
}

func (s svcServiceAPI) SetAlias(msg dbus.Message, name string, collection dbus.ObjectPath) (derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassService {
		return svcErrUnknownObject("SetAlias on non-service path")
	}
	if _, _, _, err := s.d.svcGate(msg); err != nil {
		return err
	}
	// Single-collection model: writes pointing at the collection are benign;
	// anything else would alias into a void.
	if collection != svcCollectionPath() && collection != "/" {
		return svcErrInvalidArgs("unknown collection " + string(collection))
	}
	return nil
}

// --- Collection ----------------------------------------------------------

func (c svcCollectionAPI) Delete(msg dbus.Message) (prompt dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassCollection {
		return "/", svcErrUnknownObject("Delete on non-collection path")
	}
	if _, _, _, err := c.d.svcGate(msg); err != nil {
		return "/", err
	}
	// The singleton vault is not deletable.
	return "/", svcErrAccessDenied("the login collection cannot be deleted")
}

func (c svcCollectionAPI) SearchItems(msg dbus.Message, attrs map[string]string) (results []dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassCollection {
		return nil, svcErrUnknownObject("SearchItems on non-collection path")
	}
	if _, _, _, err := c.d.svcGate(msg); err != nil {
		return nil, err
	}
	return c.d.searchItems(attrs), nil
}

func (c svcCollectionAPI) CreateItem(msg dbus.Message, props map[string]dbus.Variant, secret svcSecret, replace bool) (item dbus.ObjectPath, prompt dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	if svcClassify(svcMsgPath(msg)) != svcClassCollection {
		return "/", "/", svcErrUnknownObject("CreateItem on non-collection path")
	}
	if _, _, _, err := c.d.svcGate(msg); err != nil {
		return "/", "/", err
	}
	sess, err := c.d.sessionFor(msg, secret.Session)
	if err != nil {
		return "/", "/", err
	}
	plain, derr2 := sess.codec.decrypt(secret.Params, secret.Value)
	if derr2 != nil {
		return "/", "/", svcErrInvalidArgs("secret decode: " + derr2.Error())
	}
	if len(plain) > svcMaxSecretBytes {
		return "/", "/", svcErrInvalidArgs("secret exceeds 1 MiB")
	}

	attrs := svcAttrsFromProps(props)
	label, _ := props["org.freedesktop.Secret.Item.Label"].Value().(string)
	itemType, _ := props["org.freedesktop.Secret.Item.Type"].Value().(string)
	key := svcItemKey(attrs)
	svc, acct, _ := svcSplitKey(key)

	path, cerr := c.d.createItem(key, svc, acct, string(plain), attrs, label, itemType, replace)
	if cerr != nil {
		return "/", "/", cerr
	}
	if path == "" {
		return "/", "/", svcErrInvalidArgs("item exists (set replace=true)")
	}
	// Writes succeed while locked by native-store design — no prompt needed.
	return dbus.ObjectPath(path), "/", nil
}

// --- Item ----------------------------------------------------------------

func (i svcItemAPI) Delete(msg dbus.Message) (prompt dbus.ObjectPath, derr *dbus.Error) {
	defer svcGuard(&derr)
	path := svcMsgPath(msg)
	if svcClassify(path) != svcClassItem {
		return "/", svcErrUnknownObject("Delete on non-item path")
	}
	if _, _, _, err := i.d.svcGate(msg); err != nil {
		return "/", err
	}
	it, err := i.d.itemAt(path)
	if err != nil {
		return "/", err
	}
	svc, acct, _ := svcSplitKey(it.Key)
	if derr := i.d.store.Delete(svc, acct); derr != nil {
		return "/", svcErrFrom(derr)
	}
	i.d.mu.Lock()
	delete(i.d.index.Items, string(path))
	if err := i.d.index.save(); err != nil {
		WriteLog("provider: index save after delete: %v", err)
	}
	i.d.mu.Unlock()
	i.d.emitItemDeleted(path)
	return "/", nil
}

func (i svcItemAPI) GetSecret(msg dbus.Message, sessionPath dbus.ObjectPath) (secret svcSecret, derr *dbus.Error) {
	defer svcGuard(&derr)
	path := svcMsgPath(msg)
	if svcClassify(path) != svcClassItem {
		return svcSecret{}, svcErrUnknownObject("GetSecret on non-item path")
	}
	if _, _, _, err := i.d.svcGate(msg); err != nil {
		return svcSecret{}, err
	}
	sess, err := i.d.sessionFor(msg, sessionPath)
	if err != nil {
		return svcSecret{}, err
	}
	if i.d.locked() {
		return svcSecret{}, svcErrIsLocked()
	}
	it, err := i.d.itemAt(path)
	if err != nil {
		return svcSecret{}, err
	}
	svc, acct, _ := svcSplitKey(it.Key)
	plain, gerr := i.d.store.Get(svc, acct)
	if gerr != nil {
		return svcSecret{}, svcErrFrom(gerr)
	}
	params, value, cerr := sess.codec.encrypt([]byte(plain))
	if cerr != nil {
		return svcSecret{}, svcErrFailed(cerr.Error())
	}
	WriteLog("provider: getsecret %s sender=%s", path, svcMsgSender(msg))
	return svcSecret{Session: sessionPath, Params: params, Value: value, ContentType: "text/plain"}, nil
}

func (i svcItemAPI) SetSecret(msg dbus.Message, secret svcSecret) (derr *dbus.Error) {
	defer svcGuard(&derr)
	path := svcMsgPath(msg)
	if svcClassify(path) != svcClassItem {
		return svcErrUnknownObject("SetSecret on non-item path")
	}
	if _, _, _, err := i.d.svcGate(msg); err != nil {
		return err
	}
	sess, err := i.d.sessionFor(msg, secret.Session)
	if err != nil {
		return err
	}
	plain, derr2 := sess.codec.decrypt(secret.Params, secret.Value)
	if derr2 != nil {
		return svcErrInvalidArgs("secret decode: " + derr2.Error())
	}
	if len(plain) > svcMaxSecretBytes {
		return svcErrInvalidArgs("secret exceeds 1 MiB")
	}
	it, err := i.d.itemAt(path)
	if err != nil {
		return err
	}
	svc, acct, _ := svcSplitKey(it.Key)
	if serr := i.d.store.Set(svc, acct, string(plain)); serr != nil {
		return svcErrFrom(serr)
	}
	i.d.emitItemChanged(path)
	return nil
}

// --- Session -------------------------------------------------------------

func (s svcSessionAPI) Close(msg dbus.Message) (derr *dbus.Error) {
	defer svcGuard(&derr)
	path := svcMsgPath(msg)
	if svcClassify(path) != svcClassSession {
		return svcErrUnknownObject("Close on non-session path")
	}
	sender := svcMsgSender(msg)
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	sess, ok := s.d.sessions[path]
	if !ok {
		return svcErrNoSession()
	}
	if sess.owner != sender {
		return svcErrAccessDenied("session owned by another client")
	}
	delete(s.d.sessions, path)
	return nil
}

// --- Prompt --------------------------------------------------------------

func (p svcPromptAPI) Prompt(msg dbus.Message, _ string) (derr *dbus.Error) {
	defer svcGuard(&derr)
	path := svcMsgPath(msg)
	if svcClassify(path) != svcClassPrompt {
		return svcErrUnknownObject("Prompt on non-prompt path")
	}
	return p.d.drivePrompt(path, svcMsgSender(msg))
}

func (p svcPromptAPI) Dismiss(msg dbus.Message) (derr *dbus.Error) {
	defer svcGuard(&derr)
	path := svcMsgPath(msg)
	if svcClassify(path) != svcClassPrompt {
		return svcErrUnknownObject("Dismiss on non-prompt path")
	}
	return p.d.dismissPrompt(path, svcMsgSender(msg))
}

// --- shared machinery ----------------------------------------------------

// sessionFor resolves a session path and verifies the sender owns it —
// a foreign session cannot be used (read or write) by another client.
func (d *svcDaemon) sessionFor(msg dbus.Message, path dbus.ObjectPath) (*svcSession, *dbus.Error) {
	sender := svcMsgSender(msg)
	d.mu.Lock()
	defer d.mu.Unlock()
	sess, ok := d.sessions[path]
	if !ok {
		return nil, svcErrNoSession()
	}
	if sess.owner != sender {
		return nil, svcErrAccessDenied("session owned by another client")
	}
	return sess, nil
}

func (d *svcDaemon) countSessionsForUIDLocked(uid uint32) int {
	n := 0
	for _, s := range d.sessions {
		if s.uid == uid {
			n++
		}
	}
	return n
}

// svcAttrsFromProps pulls the a{ss} attribute dict out of item properties.
func svcAttrsFromProps(props map[string]dbus.Variant) map[string]string {
	out := map[string]string{}
	if raw, ok := props["org.freedesktop.Secret.Item.Attributes"].Value().(map[string]string); ok {
		for k, v := range raw {
			out[k] = v
		}
	}
	return out
}

// emitItemChanged fires ItemChanged on the collection — async, best-effort.
func (d *svcDaemon) emitItemChanged(path dbus.ObjectPath) {
	_ = d.conn.Emit(svcCollectionPath(), "org.freedesktop.Secret.Collection.ItemChanged", path)
}

// emitItemCreated fires ItemCreated on the collection for a brand-new item.
func (d *svcDaemon) emitItemCreated(path dbus.ObjectPath) {
	_ = d.conn.Emit(svcCollectionPath(), "org.freedesktop.Secret.Collection.ItemCreated", path)
}

// emitItemDeleted fires ItemDeleted on the collection after removal.
func (d *svcDaemon) emitItemDeleted(path dbus.ObjectPath) {
	_ = d.conn.Emit(svcCollectionPath(), "org.freedesktop.Secret.Collection.ItemDeleted", path)
}

// emitPropsChanged fires org.freedesktop.DBus.Properties.PropertiesChanged
// on the object's own path — clients watching Locked/Label/Attributes see
// every mutation the moment it lands.
func (d *svcDaemon) emitPropsChanged(path dbus.ObjectPath, iface string, changed map[string]dbus.Variant) {
	_ = d.conn.Emit(path, "org.freedesktop.DBus.Properties.PropertiesChanged", iface, changed, []string{})
}

// createItem writes to the native store (works locked by design) and indexes.
// The path return is "" only when replace=false blocks an existing item —
// store/index failures come back through err so callers report them as
// Failed, not "item exists".
func (d *svcDaemon) createItem(key, svc, acct, secret string, attrs map[string]string, label, itemType string, replace bool) (string, *dbus.Error) {
	d.mu.Lock()
	// Reconcile first: a CLI-created row not yet indexed must still block
	// replace=false, otherwise the write silently clobbers it.
	if err := d.reconcile(); err != nil {
		d.mu.Unlock()
		return "", svcErrFailed(err.Error())
	}
	path := string(svcItemPath(svcItemID(key)))
	prev, existed := d.index.Items[path]
	switch {
	case existed && !replace:
		d.mu.Unlock()
		return "", nil
	case len(d.index.Items) >= svcMaxItemsGlobal && !existed:
		d.mu.Unlock()
		return "", svcErrInvalidArgs(fmt.Sprintf("item budget exhausted (%d)", svcMaxItemsGlobal))
	case svcAttrBytes(attrs) > svcMaxAttrBytes:
		d.mu.Unlock()
		return "", svcErrInvalidArgs("attributes exceed 64 KiB")
	}
	if err := d.store.Set(svc, acct, secret); err != nil {
		d.mu.Unlock()
		WriteLog("provider: createitem %s: %v", svc+"/"+acct, err)
		return "", svcErrFrom(err)
	}
	if label == "" {
		label = fmt.Sprintf("%s / %s", svc, acct)
	}
	now := d.now()
	row := &svcItem{Path: path, Key: key, Label: label, Attrs: attrs, ItemType: itemType, Created: now, Modified: now}
	if existed {
		row.Created = prev.Created
	}
	d.index.Items[path] = row
	if err := d.index.save(); err != nil {
		// store.Set already committed — roll back the in-memory row so a
		// retry sees clean state (reconcile re-indexes the stored secret),
		// report the partial commit, and emit no success signal.
		if existed {
			d.index.Items[path] = prev
		} else {
			delete(d.index.Items, path)
		}
		d.mu.Unlock()
		WriteLog("provider: index save after set: %v", err)
		return "", svcErrFailed(fmt.Sprintf("secret stored but index persist failed: %v", err))
	}
	d.mu.Unlock()
	if existed {
		d.emitItemChanged(dbus.ObjectPath(path))
	} else {
		d.emitItemCreated(dbus.ObjectPath(path))
	}
	return path, nil
}

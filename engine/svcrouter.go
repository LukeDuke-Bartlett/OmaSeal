package main

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

// Object routing. godbus's ExportSubtree merges every exported interface at
// every path under the subtree, and member names collide across Secret
// Service interfaces (Delete on Item+Collection, SearchItems on
// Service+Collection with different signatures). So every method checks its
// path class explicitly, and each interface is implemented by its own Go
// type — a collision that reaches the "wrong" method still resolves the same
// underlying object by path, making empty-interface dispatch harmless.
//
// godbus's built-in Introspectable only enumerates statically-registered
// children, so the router serves Introspect itself — per path class.

type svcPathClass int

const (
	svcClassNone svcPathClass = iota
	svcClassService
	svcClassCollection
	svcClassItem
	svcClassSession
	svcClassPrompt
)

const svcCollectionID = "login"

func svcCollectionPath() dbus.ObjectPath {
	return dbus.ObjectPath(string(svcBasePath) + "/collection/" + svcCollectionID)
}

func svcClassify(path dbus.ObjectPath) svcPathClass {
	rest, ok := strings.CutPrefix(string(path), string(svcBasePath))
	if !ok {
		return svcClassNone
	}
	rest = strings.Trim(rest, "/")
	switch {
	case rest == "":
		return svcClassService
	case rest == "collection/"+svcCollectionID:
		return svcClassCollection
	case strings.HasPrefix(rest, "aliases/"):
		return svcClassCollection // aliases serve the Collection interface
	case strings.HasPrefix(rest, "session/") && !strings.Contains(rest[8:], "/"):
		return svcClassSession
	case strings.HasPrefix(rest, "prompt/") && !strings.Contains(rest[7:], "/"):
		return svcClassPrompt
	case strings.HasPrefix(rest, "collection/"+svcCollectionID+"/") && !strings.Contains(rest[len("collection/"+svcCollectionID)+1:], "/"):
		return svcClassItem
	}
	return svcClassNone
}

// svcMsgPath pulls the called object path from an injected dbus.Message.
func svcMsgPath(msg dbus.Message) dbus.ObjectPath {
	if p, ok := msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath); ok {
		return p
	}
	return ""
}

// svcMsgSender pulls the caller's unique bus name from the message.
func svcMsgSender(msg dbus.Message) string {
	if s, ok := msg.Headers[dbus.FieldSender].Value().(string); ok {
		return s
	}
	return ""
}

// --- exported per-interface method sets -----------------------------------

// One Go type per D-Bus interface — member-name collisions across
// interfaces require distinct method sets. Each embeds *svcDaemon.
type (
	svcServiceAPI    struct{ d *svcDaemon }
	svcCollectionAPI struct{ d *svcDaemon }
	svcItemAPI       struct{ d *svcDaemon }
	svcSessionAPI    struct{ d *svcDaemon }
	svcPromptAPI     struct{ d *svcDaemon }
	svcPropsAPI      struct{ d *svcDaemon }
	svcIntroAPI      struct{ d *svcDaemon }
)

// installObjects exports every interface at the service subtree.
func (d *svcDaemon) installObjects() error {
	api := []struct {
		iface string
		obj   any
	}{
		{"org.freedesktop.Secret.Service", svcServiceAPI{d}},
		{"org.freedesktop.Secret.Collection", svcCollectionAPI{d}},
		{"org.freedesktop.Secret.Item", svcItemAPI{d}},
		{"org.freedesktop.Secret.Session", svcSessionAPI{d}},
		{"org.freedesktop.Secret.Prompt", svcPromptAPI{d}},
		{"org.freedesktop.DBus.Properties", svcPropsAPI{d}},
		{"org.freedesktop.DBus.Introspectable", svcIntroAPI{d}},
	}
	for _, e := range api {
		if err := d.conn.ExportSubtree(e.obj, svcBasePath, e.iface); err != nil {
			return fmt.Errorf("export %s: %w", e.iface, err)
		}
	}
	return nil
}

// --- Introspectable — served by our own dispatch --------------------------

func (svcIntroAPI) Introspect(msg dbus.Message) (data string, derr *dbus.Error) {
	defer svcGuard(&derr)
	path := svcMsgPath(msg)
	var node *introspect.Node
	switch svcClassify(path) {
	case svcClassService:
		node = svcServiceIntrospect()
	case svcClassCollection:
		node = svcCollectionIntrospect()
	case svcClassItem:
		node = svcItemIntrospect()
	case svcClassSession:
		node = svcSessionIntrospect()
	case svcClassPrompt:
		node = svcPromptIntrospect()
	default:
		return "", svcErrUnknownObject(string(path))
	}
	raw, err := xml.Marshal(node)
	if err != nil {
		return "", svcErrFailed(err.Error())
	}
	return introspect.IntrospectDeclarationString + string(raw), nil
}

func svcInterfaceDoc(name string, members []introspect.Method, props []introspect.Property) introspect.Interface {
	return introspect.Interface{Name: name, Methods: members, Properties: props}
}

// svcPropsDoc is the shared org.freedesktop.DBus.Properties fragment —
// every node exports it and emits PropertiesChanged.
func svcPropsDoc() introspect.Interface {
	return introspect.Interface{
		Name: "org.freedesktop.DBus.Properties",
		Signals: []introspect.Signal{
			{Name: "PropertiesChanged", Args: []introspect.Arg{
				{Name: "interface", Type: "s"}, {Name: "changed_properties", Type: "a{sv}"}, {Name: "invalidated_properties", Type: "as"},
			}},
		},
	}
}

// svcIntroDoc is the shared org.freedesktop.DBus.Introspectable fragment.
func svcIntroDoc() introspect.Interface {
	return introspect.Interface{Name: "org.freedesktop.DBus.Introspectable", Methods: []introspect.Method{
		{Name: "Introspect", Args: []introspect.Arg{{Name: "data", Type: "s", Direction: "out"}}},
	}}
}

// svcItemSignals are the Collection's item-lifecycle signals.
var svcItemSignals = []introspect.Signal{
	{Name: "ItemCreated", Args: []introspect.Arg{{Name: "item", Type: "o"}}},
	{Name: "ItemDeleted", Args: []introspect.Arg{{Name: "item", Type: "o"}}},
	{Name: "ItemChanged", Args: []introspect.Arg{{Name: "item", Type: "o"}}},
}

func svcServiceIntrospect() *introspect.Node {
	return &introspect.Node{Interfaces: []introspect.Interface{
		svcInterfaceDoc("org.freedesktop.Secret.Service", []introspect.Method{
			{Name: "OpenSession", Args: []introspect.Arg{{Name: "algorithm", Type: "s", Direction: "in"}, {Name: "input", Type: "v", Direction: "in"}, {Name: "output", Type: "v", Direction: "out"}, {Name: "result", Type: "o", Direction: "out"}}},
			{Name: "CreateCollection", Args: []introspect.Arg{{Name: "properties", Type: "a{sv}", Direction: "in"}, {Name: "alias", Type: "s", Direction: "in"}, {Name: "collection", Type: "o", Direction: "out"}, {Name: "prompt", Type: "o", Direction: "out"}}},
			{Name: "SearchItems", Args: []introspect.Arg{{Name: "attributes", Type: "a{ss}", Direction: "in"}, {Name: "unlocked", Type: "ao", Direction: "out"}, {Name: "locked", Type: "ao", Direction: "out"}}},
			{Name: "Unlock", Args: []introspect.Arg{{Name: "objects", Type: "ao", Direction: "in"}, {Name: "unlocked", Type: "ao", Direction: "out"}, {Name: "prompt", Type: "o", Direction: "out"}}},
			{Name: "Lock", Args: []introspect.Arg{{Name: "objects", Type: "ao", Direction: "in"}, {Name: "locked", Type: "ao", Direction: "out"}, {Name: "prompt", Type: "o", Direction: "out"}}},
			{Name: "GetSecrets", Args: []introspect.Arg{{Name: "items", Type: "ao", Direction: "in"}, {Name: "session", Type: "o", Direction: "in"}, {Name: "secrets", Type: "a{o(oayays)}", Direction: "out"}}},
			{Name: "ReadAlias", Args: []introspect.Arg{{Name: "name", Type: "s", Direction: "in"}, {Name: "collection", Type: "o", Direction: "out"}}},
			{Name: "SetAlias", Args: []introspect.Arg{{Name: "name", Type: "s", Direction: "in"}, {Name: "collection", Type: "o", Direction: "in"}}},
		}, []introspect.Property{
			{Name: "Collections", Type: "ao", Access: "read"},
		}),
		svcPropsDoc(),
		svcIntroDoc(),
	}}
}

func svcCollectionIntrospect() *introspect.Node {
	iface := svcInterfaceDoc("org.freedesktop.Secret.Collection", []introspect.Method{
		{Name: "Delete", Args: []introspect.Arg{{Name: "prompt", Type: "o", Direction: "out"}}},
		{Name: "SearchItems", Args: []introspect.Arg{{Name: "attributes", Type: "a{ss}", Direction: "in"}, {Name: "results", Type: "ao", Direction: "out"}}},
		{Name: "CreateItem", Args: []introspect.Arg{{Name: "properties", Type: "a{sv}", Direction: "in"}, {Name: "secret", Type: "(oayays)", Direction: "in"}, {Name: "replace", Type: "b", Direction: "in"}, {Name: "item", Type: "o", Direction: "out"}, {Name: "prompt", Type: "o", Direction: "out"}}},
	}, []introspect.Property{
		{Name: "Items", Type: "ao", Access: "read"},
		{Name: "Label", Type: "s", Access: "readwrite"},
		{Name: "Locked", Type: "b", Access: "read"},
		{Name: "Created", Type: "t", Access: "read"},
		{Name: "Modified", Type: "t", Access: "read"},
	})
	iface.Signals = svcItemSignals
	return &introspect.Node{Interfaces: []introspect.Interface{
		iface,
		svcPropsDoc(),
		svcIntroDoc(),
	}}
}

func svcItemIntrospect() *introspect.Node {
	return &introspect.Node{Interfaces: []introspect.Interface{
		svcInterfaceDoc("org.freedesktop.Secret.Item", []introspect.Method{
			{Name: "Delete", Args: []introspect.Arg{{Name: "prompt", Type: "o", Direction: "out"}}},
			{Name: "GetSecret", Args: []introspect.Arg{{Name: "session", Type: "o", Direction: "in"}, {Name: "secret", Type: "(oayays)", Direction: "out"}}},
			{Name: "SetSecret", Args: []introspect.Arg{{Name: "secret", Type: "(oayays)", Direction: "in"}}},
		}, []introspect.Property{
			{Name: "Locked", Type: "b", Access: "read"},
			{Name: "Attributes", Type: "a{ss}", Access: "readwrite"},
			{Name: "Label", Type: "s", Access: "readwrite"},
			{Name: "Type", Type: "s", Access: "readwrite"},
			{Name: "Created", Type: "t", Access: "read"},
			{Name: "Modified", Type: "t", Access: "read"},
		}),
		svcPropsDoc(),
		svcIntroDoc(),
	}}
}

func svcSessionIntrospect() *introspect.Node {
	return &introspect.Node{Interfaces: []introspect.Interface{
		svcInterfaceDoc("org.freedesktop.Secret.Session", []introspect.Method{
			{Name: "Close"},
		}, nil),
		svcPropsDoc(),
		svcIntroDoc(),
	}}
}

func svcPromptIntrospect() *introspect.Node {
	return &introspect.Node{Interfaces: []introspect.Interface{
		func() introspect.Interface {
			i := svcInterfaceDoc("org.freedesktop.Secret.Prompt", []introspect.Method{
				{Name: "Prompt", Args: []introspect.Arg{{Name: "window-id", Type: "s", Direction: "in"}}},
				{Name: "Dismiss"},
			}, nil)
			i.Signals = []introspect.Signal{
				{Name: "Completed", Args: []introspect.Arg{
					{Name: "dismissed", Type: "b"}, {Name: "result", Type: "v"},
				}},
			}
			return i
		}(),
		svcPropsDoc(),
		svcIntroDoc(),
	}}
}

// --- org.freedesktop.DBus.Properties — store-backed per path class --------

// Get dispatches a property read on the called path.
func (p svcPropsAPI) Get(msg dbus.Message, iface, name string) (v dbus.Variant, derr *dbus.Error) {
	defer svcGuard(&derr)
	if _, _, _, err := p.d.svcGate(msg); err != nil {
		return dbus.Variant{}, err
	}
	path := svcMsgPath(msg)
	v, err := p.d.propGet(path, iface, name)
	if err != nil {
		return dbus.Variant{}, err
	}
	return v, nil
}

func (p svcPropsAPI) Set(msg dbus.Message, iface, name string, v dbus.Variant) (derr *dbus.Error) {
	defer svcGuard(&derr)
	if _, _, _, err := p.d.svcGate(msg); err != nil {
		return err
	}
	return p.d.propSet(svcMsgPath(msg), iface, name, v)
}

func (p svcPropsAPI) GetAll(msg dbus.Message, iface string) (all map[string]dbus.Variant, derr *dbus.Error) {
	defer svcGuard(&derr)
	if _, _, _, err := p.d.svcGate(msg); err != nil {
		return nil, err
	}
	return p.d.propGetAll(svcMsgPath(msg), iface)
}

// propGet serves reads from live daemon/store state — never export-time
// snapshots (the gopass-secret-service staleness bug).
func (d *svcDaemon) propGet(path dbus.ObjectPath, iface, name string) (dbus.Variant, *dbus.Error) {
	switch iface {
	case "org.freedesktop.Secret.Service":
		if svcClassify(path) != svcClassService {
			return dbus.Variant{}, svcErrUnknownObject(string(path))
		}
		if name == "Collections" {
			return dbus.MakeVariant([]dbus.ObjectPath{svcCollectionPath()}), nil
		}
	case "org.freedesktop.Secret.Collection":
		if svcClassify(path) != svcClassCollection {
			return dbus.Variant{}, svcErrUnknownObject(string(path))
		}
		switch name {
		case "Items":
			return dbus.MakeVariant(d.itemPaths()), nil
		case "Label":
			d.mu.Lock()
			label := d.index.CollectionLabel
			d.mu.Unlock()
			if label == "" {
				label = svcCollectionID
			}
			return dbus.MakeVariant(label), nil
		case "Locked":
			return dbus.MakeVariant(d.locked()), nil
		case "Created", "Modified":
			return dbus.MakeVariant(uint64(0)), nil
		}
	case "org.freedesktop.Secret.Item":
		it, err := d.itemAt(path)
		if err != nil {
			return dbus.Variant{}, err
		}
		switch name {
		case "Locked":
			return dbus.MakeVariant(d.locked()), nil
		case "Attributes":
			return dbus.MakeVariant(it.Attrs), nil
		case "Label":
			return dbus.MakeVariant(it.Label), nil
		case "Type":
			return dbus.MakeVariant(it.ItemType), nil
		case "Created":
			return dbus.MakeVariant(uint64(it.Created.Unix())), nil
		case "Modified":
			return dbus.MakeVariant(uint64(it.Modified.Unix())), nil
		}
	}
	return dbus.Variant{}, svcErrUnknownObject(iface + "." + name)
}

func (d *svcDaemon) propSet(path dbus.ObjectPath, iface, name string, v dbus.Variant) *dbus.Error {
	if iface != "org.freedesktop.Secret.Item" && iface != "org.freedesktop.Secret.Collection" {
		return svcErrInvalidArgs("read-only interface " + iface)
	}
	switch iface {
	case "org.freedesktop.Secret.Collection":
		if svcClassify(path) != svcClassCollection || name != "Label" {
			return svcErrInvalidArgs(name)
		}
		s, ok := v.Value().(string)
		if !ok {
			return svcErrInvalidArgs(name)
		}
		d.mu.Lock()
		d.index.CollectionLabel = s
		if err := d.index.save(); err != nil {
			d.mu.Unlock()
			return svcErrFailed(err.Error())
		}
		d.mu.Unlock()
		d.emitPropsChanged(path, iface, map[string]dbus.Variant{name: v})
		return nil
	case "org.freedesktop.Secret.Item":
		it, derr := d.itemAt(path)
		if derr != nil {
			return derr
		}
		switch name {
		case "Label":
			if s, ok := v.Value().(string); ok {
				return d.mutateItem(path, it, name, v, func() { it.Label = s })
			}
		case "Attributes":
			if m, ok := v.Value().(map[string]string); ok {
				if svcAttrBytes(m) > svcMaxAttrBytes {
					return svcErrInvalidArgs("attributes exceed 64 KiB")
				}
				// service/account are the item's identity — a dict that
				// implies a different store key would orphan the secret it
				// points at, so SearchItems lies about what's stored.
				if svcItemKey(m) != it.Key {
					return svcErrInvalidArgs("service/account are item identity and cannot change")
				}
				return d.mutateItem(path, it, name, v, func() { it.Attrs = m })
			}
		case "Type":
			if s, ok := v.Value().(string); ok {
				return d.mutateItem(path, it, name, v, func() { it.ItemType = s })
			}
		}
		return svcErrInvalidArgs(name)
	}
	return svcErrInvalidArgs(iface)
}

func (d *svcDaemon) propGetAll(path dbus.ObjectPath, iface string) (map[string]dbus.Variant, *dbus.Error) {
	out := map[string]dbus.Variant{}
	names := map[string][]string{
		"org.freedesktop.Secret.Service":    {"Collections"},
		"org.freedesktop.Secret.Collection": {"Items", "Label", "Locked", "Created", "Modified"},
		"org.freedesktop.Secret.Item":       {"Locked", "Attributes", "Label", "Type", "Created", "Modified"},
	}
	for _, name := range names[iface] {
		if v, err := d.propGet(path, iface, name); err == nil {
			out[name] = v
		}
	}
	return out, nil
}

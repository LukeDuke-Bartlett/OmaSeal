package main

import (
	"github.com/godbus/dbus/v5"
)

// Secret Service error names — libsecret branches on the name, not the
// message, so these must be the real spec names. Non-secret-service errors
// ride standard org.freedesktop.DBus.Error.* names.
const (
	svcErrNameIsLocked     = "org.freedesktop.Secret.Error.IsLocked"
	svcErrNameNoSession    = "org.freedesktop.Secret.Error.NoSession"
	svcErrNameNoSuchObj    = "org.freedesktop.Secret.Error.NoSuchObject"
	svcErrNameAccessDenied = "org.freedesktop.DBus.Error.AccessDenied"
	svcErrNameInvalidArgs  = "org.freedesktop.DBus.Error.InvalidArgs"
	svcErrNameNotSupported = "org.freedesktop.DBus.Error.NotSupported"
	svcErrNameUnknownObj   = "org.freedesktop.DBus.Error.UnknownObject"
	svcErrNameFailed       = "org.freedesktop.DBus.Error.Failed"
)

func svcErrIsLocked() *dbus.Error {
	return dbus.NewError(svcErrNameIsLocked, []any{"collection or item is locked"})
}
func svcErrNoSession() *dbus.Error {
	return dbus.NewError(svcErrNameNoSession, []any{"unknown session"})
}
func svcErrNoSuchObject(what string) *dbus.Error {
	return dbus.NewError(svcErrNameNoSuchObj, []any{what})
}
func svcErrAccessDenied(what string) *dbus.Error {
	return dbus.NewError(svcErrNameAccessDenied, []any{what})
}
func svcErrInvalidArgs(what string) *dbus.Error {
	return dbus.NewError(svcErrNameInvalidArgs, []any{what})
}
func svcErrNotSupported(what string) *dbus.Error {
	return dbus.NewError(svcErrNameNotSupported, []any{what})
}
func svcErrUnknownObject(what string) *dbus.Error {
	return dbus.NewError(svcErrNameUnknownObj, []any{what})
}
func svcErrFailed(what string) *dbus.Error {
	return dbus.NewError(svcErrNameFailed, []any{what})
}

// svcErrFrom maps an internal error onto the wire error — omasealError
// codes first, then the native-store sentinels.
func svcErrFrom(err error) *dbus.Error {
	if err == nil {
		return nil
	}
	switch codeFromError(err) {
	case "locked", "store_uninitialized", "agent_locked":
		return svcErrIsLocked()
	case "not_found":
		return svcErrNoSuchObject(err.Error())
	case "invalid_name", "invalid_secret":
		return svcErrInvalidArgs(err.Error())
	case "manifest_denied", "agent_unauthorized":
		return svcErrAccessDenied(err.Error())
	}
	return svcErrFailed(err.Error())
}

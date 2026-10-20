# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Secret

A single stored credential addressed by a `(service, account)` pair — `service` names what the credential is for, `account` names which identity within it. The pair is the canonical key everywhere a secret is stored, listed, or resolved.

## OmaSeal agent session

The unlocked window in which `omaseal` answers secret reads without prompting. Unlocking starts a session with a finite lifetime; when it lapses, reads return a locked error while metadata operations such as listing and deleting may still succeed — the lock gates secret disclosure, not store structure.

## Secrets panel

The Omarchy shell plugin (`Panel.qml` plus sibling components) that fronts the secret store: it lists, filters, copies to the clipboard, adds, edits, and deletes secrets, and hosts the inline unlock field that opens an agent session. It is a client of `omaseal`, not an authority — all mutations go through the CLI.

## Secret Service

The `org.freedesktop.secrets` D-Bus API that desktop apps and agents call for credential storage. Only one daemon can own the bus name at a time; on this system that owner is what actually answers every libsecret consumer, so which provider holds the name decides which store is live.

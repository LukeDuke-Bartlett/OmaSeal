---
module: secrets-panel
date: 2026-10-19
problem_type: developer_experience
component: frontend
severity: medium
applies_when:
  - splitting a monolithic QML or Quickshell file into sibling component files
  - choosing a root type for a non-visual logic component in QML
  - referencing ids, models, or functions across QML file boundaries
  - writing static guards for a QML-based plugin or shell
tags:
  - qml
  - quickshell
  - component-extraction
  - qtobject
  - file-scoped-ids
  - silent-failure
  - static-guards
related_components:
  - testing_framework
---

# Splitting a QML monolith fails in ways no static check can see — verify with a live load

## Context

The secrets panel was a 1,268-line `Panel.qml` monolith that decomposed into
six sibling files (`Panel.qml`, `PanelJobs.qml`, `PanelModel.qml`,
`SecretsView.qml`, `AgentSection.qml`, `AddEditForm.qml`). Every static gate
passed — qmllint reported only the pre-existing unresolved-import noise, and
the contract greps were green — yet on first deploy the panel silently never
opened. Two distinct QML semantic rules broke only at load time, and a third
class of hazard (Process spawn failure) surfaced in review afterward.

Session-history corroboration: a prior monolith→sibling split elsewhere in
this workspace (wisp `Companion.qml`, ~1,000→196 lines) likewise passed its
full automated gate — 1,146 tests and 549 snapshot comparisons — and still
shipped a functional bug caught only on screenshot review (session history).
The pattern is systemic, not a one-off.

## Guidance

Three contracts change invisibly when a monolith becomes siblings. Check each
explicitly, then verify with a live load — not a linter.

**1. Root-type containment: non-visual logic needs `Item`, not `QtObject`.**

`QtObject`'s default property is `data: list<QtObject>` — children must be
QtObject-typed. `ListModel`, `Process`, and `Component` are not. Declaring
them under a `QtObject` root fails at instantiation ("Unable to assign …"),
and so does `property var x: Process {}` in this runtime (a *typed*
declaration — `property Process x: Process {}` — does work under `QtObject`,
which is how `PluginRegistry.qml` holds its Processes; pure
property/signal/function singletons use `QtObject` roots throughout the
shell). The working pattern for a container of bare object children — used
by every Omarchy shell file that holds non-QtObject children — is an `Item`
root with `id:` children:

```qml
// PanelJobs.qml:7 — works; a QtObject root rejects every child below
Item {
  Process { id: listProc ... }
  Timer   { id: clipboardClearTimer ... }
  Component { id: setProcComponent ... }
}
```

The plan that produced this split prescribed `QtObject` roots; the
prescription was falsified at runtime. A plan review cannot substitute for a
load check.

**2. Ids are file-scoped — siblings communicate through properties, not ids.**

A QML `id` resolves only inside the document that declares it. In the
monolith `secretsModel` was visible everywhere; after extraction,
`store.secretsModel` through an object reference read `undefined` because an
id is not a property. Every cross-file reference must become an injected
property or a signal at the boundary:

```qml
// PanelModel.qml:32-33 — real properties so sibling files can reach the models
property var secretsModel: ListModel {}
property var logModel: ListModel {}
```

**3. Static gates cannot see either failure — pin the boundary, parse every
file, then load it live.**

qmllint parses files independently: `store.secretsModel` through a `var`
resolves lazily (no error), and child-type violations surface at
instantiation, not parse. `scripts/check-panel.sh` now enforces three layers
and still cannot substitute for a live load:

- boundary declarations: injected property/signal/function names must exist
  in their owning file (`check-panel.sh` guard 5)
- every `*.qml` sibling must parse — qmllint's `[syntax]` category works even
  where `qs.*` imports don't resolve (guard 6)
- file-list drift across all five packaging surfaces (guard 3)

Live verification on Omarchy: deploy into `~/.config/omarchy/plugins/<id>/`
(the watched user-plugin dir — `~/.local/share/omarchy/` is a dev-checkout
mirror that the running shell does not scan, and deploying there verifies
nothing), wait for the plugin watch to reload, then `qs -p
/usr/share/omarchy/shell ipc call shell toggle <plugin-id> '{}'` and read
`journalctl --user -t omarchy-shell` for QML errors.

**Adjacent hazard found in review:** a Quickshell `Process` whose exec fails
skips both `onStarted` and `onExited` — `running` falling with no activity is
the only signal. Each job-queue Process (`listProc`, `copyProc`, `delProc`)
carries a `began` flag reset at launch so a dead spawn unlatches state
instead of stalling it (`PanelJobs.qml:38-42`). The first failed attempt at
this used a flag set in
`onExited` only, which misses the spawn-never-started case entirely.

## Why This Matters

These failures are silent and total: the component never instantiates, no
test fails, no lint error appears, and the only user-visible symptom is a
panel that does not open. Both root causes look clean at every stage before
runtime — plan, code review, linter, and even `qs` compile checks (which do
not exercise object-tree instantiation; session history shows this
verification gap recurring across multiple QML projects here). A future
"cleanup" that flips the roots back to `QtObject` or renames an injected
property reproduces the exact failure with zero warning.

## When to Apply

- Any QML/Quickshell monolith→sibling extraction
- Any new non-visual logic container (models, processes, timers, components)
  — default to `Item`, and audit existing `QtObject` roots for non-QtObject
  children before trusting them
- Adding files to a packaged QML plugin — the file list lives in N packaging
  surfaces, not one

## Examples

**Id-scope failure and fix (this split):**

```qml
// Broken after extraction — ids don't cross file boundaries:
Item {
  ListModel { id: secretsModel }      // other files see store.secretsModel == undefined
}

// Fixed — expose the model as a real property:
Item {
  property var secretsModel: ListModel {}
}
```

**Spawn-failure sentinel pattern (`PanelJobs.qml:101-106`):**

```qml
onRunningChanged: {
  if (!listProc.running && !jobs.listBegan) {
    jobs.refreshPending = false  // a dead spawn can't satisfy it — don't loop
    jobs.noticeSet("Failed to list secrets")
  }
}
```

## References

- Plan (carries the falsified `QtObject` prescription + erratum):
  `docs/plans/2026-10-10-001-feat-panel-extraction.md`
- Guards: `scripts/check-panel.sh`
- Prior same-class hazard (Process stdin race): `docs/plans/2026-09-13-2349-feat-omarchy-first-party-keyring-plan.md`
- Multi-surface packaging drift class: `docs/plans/2026-09-15-1351-feat-aur-omaseal-bin-packaging-plan.md`

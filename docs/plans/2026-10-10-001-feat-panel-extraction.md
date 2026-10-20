---
title: "Panel extraction — split Panel.qml into concern-grouped siblings, pipe get→wl-copy"
created_at: 2026-10-10
type: feat
topic: panel-extraction
artifact_contract: ce-unified-plan/v1
requirements: docs/brainstorms/2026-10-09---panel-extraction-requirements.md
execution: code
---

# Plan — Panel extraction

## Goal Capsule

Decompose the 1266-line `Panel.qml` into ~6 sibling QML components grouped by
concern, and remove the `getText` secret buffer so `omaseal get` output pipes
directly into `wl-copy --sensitive`. All user-visible behavior, the boundary
contract, external commands, and concurrency semantics are preserved verbatim.
Predecessor: PR #48 merged on `main` (its inline-unlock lines are inside the
moved code).

## Key constraints discovered

- **QML ids are file-scoped.** `unlockProc`, `secretsModel`, `passphraseField`
  cannot be referenced across file boundaries. Components must communicate
  through injected properties and signals — this dictates the architecture
  below. Verified: the codebase's own plugin precedent (`shell/plugins/bar`
  splits into `widgets/` + `indicators/`; `panels/tailscale` has 3 QML files)
  uses the same sibling-file mechanism, resolved by filename with no manifest
  declaration.
- **`release.yml` copies QML files by explicit name** — every new `.qml` file
  must be added to the `cp` line or release artifacts silently break.
- **`fmt.Print(secret)` emits no trailing newline** — `get | wl-copy` preserves
  secret bytes exactly (verified `handleGet`).
- The sibling `omarchy.secrets` panel's reference pipe is
  `bash -c 'omaseal get "$1" "$2" | wl-copy --sensitive'` with args passed
  positionally (no string interpolation — injection-safe).

## File layout (target)

All siblings live in the plugin root — same-dir `.qml` files resolve as
component types automatically, no `import` needed, manifest untouched.

| File | Concern | ~Lines |
|---|---|---|
| `Panel.qml` | Boundary contract (props/functions/signals), state properties, view composition, close/open lifecycle | ~300 |
| `PanelJobs.qml` (Item) | All `Process`/`Component` job objects + job functions: `copySecret`, `deleteSecret`, `saveSecret`, `unlockAgent`, `refresh`, `refreshAgentStatus`, log refresh, clipclear. Exposes `lastCopied`, `agentMode/SessionActive/Backend`, `notice` | ~450 |
| `PanelModel.qml` (Item) | `secretsModel`, `logModel`, `secrets`/`applySecrets`/`applyLogs`, filter/sort/search state, `secretKey` | ~150 |
| `SecretsView.qml` | The ListView + delegate rows + empty state | ~200 |
| `AgentSection.qml` | Agent status row, mode cycling, `passphraseField`, unlock button, fprintd notice | ~150 |
| `AddEditForm.qml` | service/account/secret fields + save/cancel + validation notice | ~150 |

> **Erratum (2026-10-19, post-implementation):** the `QtObject` root guidance below was falsified at runtime — `QtObject`'s `data` property is `list<QtObject>`, so `ListModel`/`Process`/`Component` children fail to instantiate and the panel silently never opens. `PanelJobs.qml` and `PanelModel.qml` shipped with `Item` roots and bare `id:` children. Also falsified-by-runtime: sibling files could not reach `id`s in other files — `secretsModel`/`logModel` became `property var` properties. See `docs/solutions/developer-experience/qml-sibling-split-silent-load-failures.md`.

Non-visual containers that own `Process`/`ListModel`/`Component` children use
`Item` roots — `QtObject` cannot hold those children (see erratum above);
views use `Item`/`Rectangle` per current layout. Root instantiates:

```qml
PanelJobs { id: jobs; onX: root.handleX() }
PanelModel { id: model }
// views receive jobs/model as injected props:
SecretsView { jobs: jobs; model: model.secretsModel; onCopyRequested: jobs.copySecret(...) }
```

## Copy-path fix (the leak)

- `copySecret(svc, acct)` spawns one proc running the shipped sentinel flow —
  `out=$(omaseal get "$1" "$2"; rc=$?; if [ $rc -eq 0 ]; then printf x; else
  exit $rc; fi) && out=${out%x} && [ -n "$out" ] && printf %s "$out" |
  wl-copy --sensitive` — args positional, never interpolated into the script
  string. `wl-copy` starts only after `get` succeeded and produced non-empty
  output: a failed or empty read exits before touching the clipboard, and the
  sentinel byte preserves trailing newlines that `$()` would strip.
- `getText` property deleted; `pendingCopy` queue semantics preserved (a copy
  request must always complete; double-clicks don't drop or deadlock).
- `lastCopied` identity + 30s `clipclear` timer unchanged.

## Steps

1. Create `PanelJobs.qml`/`PanelModel.qml` — move process objects + model
   verbatim; replace cross-references with injected props/signals. Root
   instantiates and wires.
2. Extract `SecretsView`/`AgentSection`/`AddEditForm` — move view blocks; root
   keeps layout container + `PanelKeyCatcher` (keyCatcher needs field ids —
   `blocked` binds against fields that now live in `AddEditForm`/`AgentSection`;
   expose `activeFocus` aliases upward as `editing` props).
3. Swap copy path to the piped proc; delete `getText`.
4. Update `.github/workflows/release.yml` `cp` line with all new filenames.
5. `scripts/check-panel.sh` — static guard: (a) no `getText` property; (b)
   boundary contract names present in `Panel.qml`; (c) set of `*.qml` files in
   the plugin dir equals the release.yml `cp` list (kills packaging drift);
   (d) no `omaseal get` stdout assigned into a QML property. Wire into CI.
6. Manual exercise pass on the live panel (below).

## Verification

- `scripts/check-panel.sh` green; `go test` unaffected (no engine change).
- Manual checklist on the installed plugin: open/close/toggle; list populate;
  copy (clipboard holds value, clears at 30s only when still that secret);
  add; edit; delete confirm (identity-armed, 5s timer); inline unlock flow
  (#48 path end-to-end); agent status row; logs; sort cycle; search; vault
  dropdown; keybindings r/a/e/s/v/backtick + field-focus blocking; Esc/close
  during in-flight unlock.

## Risks

- **id-scoping regressions** — the main hazard; every moved identifier must be
  traced (props-in/signals-out). Mitigated by the manual checklist covering
  every interactive path.
- **`sh -c` copy path** — a new `sh` spawn per copy (~1ms); positional args
  keep it injection-safe; failure surfaces via the same notice path.
- **keyCatcher `blocked`** — moved fields must still report focus; the `P0`
  fix from the review round depends on this working (alias `editing` props up).
- **No QML test harness** — the static guard + manual pass is the agreed
  substitute; a qml test harness is a separate (later) item.

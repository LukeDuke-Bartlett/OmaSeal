---
title: "Panel extraction — split Panel.qml into components, stop buffering secrets in QML"
created_at: 2026-10-09
type: feat
topic: panel-extraction
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-brainstorm
execution: code
---

# Requirements — Panel extraction

## Goal Capsule

- **Objective:** `Panel.qml` is decomposed into sibling QML components so the secrets panel is navigable and reviewable per-concern, and the copy path no longer stages secret values in QML properties — everything else about the panel behaves exactly as it does today.
- **Product authority:** user directive — extraction depth chosen 2026-10-09 as "Split + fix the leak" (decomposition plus the `getText` buffer removal; deeper re-architecture and bridge layers explicitly not chosen).
- **Predecessor:** `main` must include PR #48 (`feat/panel-inline-unlock`) before this starts — it adds `passphraseField`, `unlockPassphrase`, `agentBackend`, and the stdin-pipe unlock that this extraction must preserve.
- **Open blockers:** none.

## Product Contract

### Problem frame

`Panel.qml` is 1266 lines carrying ~30 state properties, ~330 lines of logic, nine `Process`/`Component` job types, two `ListModel`s, four pending-operation queues, a keyboard-capture surface, and ~600 lines of view code. The file outgrew single-file structure — it is on the v1.0.0 roadmap. It also buffers every copied secret in the `getText` property between `omaseal get` stdout and the `wl-copy` child — an exposure the sibling `omarchy.secrets` panel avoids by piping `get` output straight into `wl-copy`.

### Requirements

**Decomposition**

- R1. `Panel.qml` is split into sibling QML component files under the plugin directory, loaded through the same `Qt.resolvedUrl`/`Loader` mechanism `BarWidget.qml` already uses. `Panel.qml` stays the loaded root that `BarWidget.qml` instantiates and injects props into.
- R2. The split is organized by concern — boundary contract and shell integration, external-process jobs, model/filter/sort logic, and view blocks — not an arbitrary line-count chop.
- R3. `manifest.json` is unchanged: `entryPoints.barWidget` remains the only declared entry point.

**Secret-handling fix**

- R4. The copy path never stores a secret value in a QML property. `omaseal get` output reaches `wl-copy --sensitive` through a pipe (or equivalent child-stdin handoff), and the `getText` property is removed entirely.
- R5. Clipboard hygiene is unchanged: the 30-second clear still runs `omaseal clipclear` and still only clears when the clipboard still holds that secret (`lastCopied` identity tracking preserved).

**Behavior preservation**

- R6. The boundary contract is unchanged: `anchorItem`, `hostWidget`, `settings`, `popoutSwitchClosing` properties; `open`/`close`/`toggle`/`closeForPopoutSwitch` functions; the `statusChanged` signal; `switchPanel` delegation through `root.bar.switchPanelFrom`.
- R7. External commands are unchanged: `omaseal list --json`, `logs 25 --json`, `set` (stdin), `del`, `clipclear`, `agent status --json`, `agent unlock` / `agent unlock --passphrase-stdin`, and `wl-copy --sensitive`.
- R8. Concurrency semantics survive: `refreshPending`, `pendingCopy` (or its equivalent under the piped copy path — a copy request must always complete; double-clicks must not deadlock or drop), `pendingDel`, `agentStatusPending`, and the armed-by-identity delete confirm (`pendingDeleteKey` + 5 s timer keyed by `secretKey`).
- R9. The inline passphrase unlock shipped in #48 survives intact: `passphraseField` visibility rules (native backend + `ask` mode + no active session), staging/clearing of `unlockPassphrase`, `close()` wiping the field and the stage.
- R10. Keyboard semantics survive: `PanelKeyCatcher` bindings (r/a/e/s/v/backtick), field-focus `blocked`, close/tab/move/activate/delete routing.

### Non-goals

- Delegating the panel to `omarchy.secrets` / first-party surface — deferred per `docs/plans/2026-09-13-2349-feat-omarchy-first-party-keyring-plan.md` until that upstream merge outcome is known.
- Adopting the sibling panel's summon-dismiss `PanelWindow`/overlay architecture — different plugin model (`panel` kind vs `bar-widget`), explicitly out.
- A backend-bridge abstraction over the external commands — evaluated and not chosen.
- The different-UID helper daemon — separate later spike.
- Any user-visible redesign of layout, sorting, vault grouping, or flows.

### Verified during brainstorm (do not re-derive)

Grounding dossier: `/tmp/compound-engineering/ce-brainstorm/panel-extract/grounding.md` (verbatim quotes with `file:line` pointers).

- Exec surface is nine job types total — the full command list is in R7; `wl-copy` is the only non-`omaseal` binary.
- `BarWidget.qml` injects `bar`, `settings`, `anchorItem`, `hostWidget` after `Loader` completes and connects `statusChanged` to its own 30-second count refresh.
- The sibling panel's copy pipe shape (`bash -c` around `get | wl-copy`) is quoted in the dossier — it is the reference for R4's mechanics, including the `systemd-run`-detached clipclear alternative.
- Delete-confirm is armed by `secretKey(service,account)` "by identity, not index" — a subtle invariant list rebuilds must not break.

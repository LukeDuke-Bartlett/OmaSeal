# OmaSeal Roadmap

## Program view (2026-10-11): open items with difficulty

Design direction: [DESIGN.md](DESIGN.md). Written directly rather than via `ce-plan`: the repo already has per-feature plans under `docs/plans/`, so this section only adds the missing fields to the open items.

| Unit | When | Status | Difficulty | Feasibility | Simpler alternative |
|---|---|---|---|---|---|
| U1 AUR `omaseal-bin` (issue #12) | Now | blocked on registration | easy once open | AUR registration portal closed; human browser step | none; keep `install.sh` with pinned checksum |
| U2 Replace emoji social card, refresh README header | Now | done in this PR (brand proposal) | easy | owner signs off the mark | keep `docs/assets/social.png` |
| U3 Install docs versus releases: checked, `v0.4.0` release exists and is Latest, so the pin is correct | Now | verified, no action | easy | none | none |
| U4 First-party Omarchy integration (`omarchy-secrets-*`, panel, menu) | Next | open | hard | depends on `omacom/omarchy-mac` maintainers accepting a PR | ship commands + menu only (the existing phased fallback) |
| U5 BrowserOS resolves secret at request time | Next | deferred | medium | needs an `omarchy-browser` checkout | document the `omaseal run` pattern |
| U6 Panel component extraction | Later | done (#51) | medium | `Panel.qml` was 1,268 lines; now 466 lines plus sibling files (`PanelJobs.qml`, `PanelModel.qml`, `AddEditForm.qml`, `SecretsView.qml`, `AgentSection.qml`) | none left |
| U7 Different-uid policy daemon (confinement) | Later | research | hard | needs setuid or polkit brokering; large attack-surface change | state the same-uid limits plainly (already in README/ROADMAP) |
| U8 Stable v1.0 API | Later | open | medium | needs third-party consumers | freeze `service/account` and IPC only |

Simplification found: the engine carries two stores (Secret Service and native) plus `keyringmigrate.go` and `backendmigrate.go`; once the native store is the default and migration is done for existing users, the Secret Service path is the delete candidate. Not before U4's outcome is known — and not before migration verifies parity: `migrateItems` today skips a source key the native store already lists without comparing values, so "done" must mean read-and-compared equality for every addressable source item, not just presence.

---

## Done

- [x] `set/get/del/list/reveal` CLI on `gnome-keyring`
- [x] Quickshell `BarWidget` and `Panel` with click-to-open Logs page
- [x] MCP server with `open/ask/lock` agent trust modes
- [x] JSON IPC for other plugins
- [x] 1Password and Bitwarden import/fallback
- [x] Persistent, user-visible `~/.local/state/omaseal/omaseal.log`
- [x] Marketplace-ready packaging and manifest
- [x] Agent auto-detect + `omaseal mcp install-detected` — one command wires
  every installed agent (Claude, Cursor, Codex, Devin, OpenCode, …)
- [x] `omaseal setup` with self-verifying keyring round-trip (30s bounded)
- [x] `omaseal://service/account` references accepted by every command
- [x] Masked GUI prompt for `resolve` without a TTY (pinentry, `OMASEAL_GUI_PROMPT`)
- [x] Fail-closed user-presence gate for `reveal`/agent unlock — fprintd,
  else GUI confirm, else deny; `agent mode ask --ungated` opt-out (v0.4.0)
- [x] Shared `service/account` namespace with other writers
  (`omarchy-secrets-*`, keytar, seahorse): `owned` provenance flag,
  duplicate-safe set/delete
- [x] Enforced AI manifest — `omaseal manifest` robots.txt-style
  ALLOW/ASK/DENY per secret on the agent (MCP) channel; DENY also hides the
  credential from `omaseal_list`/`omaseal_stats`; quoted patterns address
  names with whitespace (`DENY "svc/acct name"`)
- [x] Usage analytics — every read path (CLI, IPC, MCP) counted;
  `omaseal stats`, sort by `used|recent|name`, `access_count`/`last_accessed`
  in list output
- [x] Organized secrets panel — expand/collapse, vault sidebar with
  per-service counts, search, sort modes, usage badges, `external` badges,
  30s conditional clipboard clear (`omaseal clipclear`)
- [x] Bounded D-Bus calls, pooled metadata reads (~0.7s at ~700 items),
  capped access log, atomic config writes
- [x] `omaseal keyring migrate` + doctor `keyring-encryption` check —
  plaintext keyrings detected and re-encrypted into `login`
- [x] Fail-closed agent policy — missing `agent.json` defaults to `ask`
- [x] Provider negative caching — repeated misses memoized (~60s) so pollers
  don't spawn `op`/`bw` per tick (#23)
- [x] Harness integration — `omaseal run -e NAME=svc/acct -- <cmd>`
  materializes secrets into a spawned MCP server's env via `exec(3)`;
  per-harness fit hints in `mcp status`/`doctor`; opt-in `apiKeyHelper`
  wiring for Claude Code (#24)
- [x] Pentest hardening — weakening mode changes fail closed without a
  presence mechanism; confirm-prompters resolve from fixed absolute paths
  only (no PATH shim adoption); presence gate extended to
  `manifest init --force`, `manifest apply` expansions, `jev enable`;
  shared `parseRuleLine` across scanner/generator/applier; audit flags
  dead tokens, shadowed rules, unquoted names (#25)
- [x] Bounded Secret Service calls + failure telemetry — every D-Bus op
  deadline-bound (12s ops / 2m promptable) so a wedged daemon returns
  `keyring_timeout` instead of parking callers forever; failure-only
  `op=` telemetry across CLI/IPC/MCP surfaces; `stats` reports failure
  counts and error-code breakdowns (#30)
- [x] Hash-chained tamper-evident audit log — every `omaseal.log` line
  carries `sha256(prev_chain ‖ line)`; `logs verify` walks the chain and
  reports the first divergent line; `logs seal`/`verify --anchor` anchors
  the head off the state dir so full-history rewrites are detectable;
  flock-serialized writers; doctor `log-chain` check; rotated logs stay
  in analytics (#31)
- [x] Postmortem — login.keyring silent re-key incident documented with
  the destructive-test isolation checklist (#29)
- [x] `Store` interface extraction behind `currentStore` — the backend
  seam all stores satisfy (#35)
- [x] Native age-encrypted backend — `backend: native` opt-in: asymmetric
  `Set`-while-locked, passphrase-scrypt identity, tmpfs session rewrap,
  flock-serialized atomic store, tamper-evident envelope. Eliminates the
  re-key class by construction (#38)
- [x] `omaseal migrate` — bulk copy Secret Service → native: idempotent,
  per-item failure isolation, provenance carried, source never written,
  `--dry-run`, consecutive-failure abort (#40)
- [x] Native key escaping — `%`/`/` percent-escaping so URL-shaped foreign
  service names (`https://…`) round-trip without collision (#41)
- [x] Session hygiene — expired sessions unlink their key files on read;
  `agent lock` propagates removal errors; corrupt-path unlinking
  deliberately avoided (torn-pair race) (#42)
- [x] `agent unlock` lazy-init — `unlockIdentity` loads the wrapped blob
  itself; the agent path no longer depends on a prior `ensureInit` (#43)
- [x] `sanitizeField` hardening — C1 controls (U+0080–9F) stripped,
  200-rune cap with truncation marker on all foreign metadata output
- [x] `omaseal doctor` backend line — reports configured backend,
  native init state, and session liveness
- [x] Panel extraction (#51) — the secrets panel is split into sibling QML
  components, and copying a secret no longer routes it through QML
- [x] Secret Service provider daemon (#50) — `omaseal provider serve` /
  `provider enable`, so `gh`, VS Code, docker credential helpers and
  `secret-tool` store into the native vault with per-caller audit
- [x] `ask-save` (#53) — a masked user dialog collects a secret for an agent
  write (`omaseal ask-save`, MCP `omaseal_ask_save`)
- [x] setec design-read (#52, #54) — notes on what the helper daemon should
  borrow, in `docs/decisions/setec-design-notes.md`

## v0.6.0 — Marketplace stable

- [x] Marketplace revalidation (#45): manifest/README/onboarding claims
  re-audited at HEAD post-native-backend and drift fixed — description
  names the opt-in native store, `migrate`/`stats` documented, the
  live-session same-uid exposure stated plainly. Installed plugin
  converted to a git-managed checkout (`omarchy plugin update` works).
  Prior pass at `547ff45`: a 4-agent pentest found and this tree fixed
  real bypasses (env-suppressed presence gate, PATH prompter shims, dead
  DENY rules on spaced names), and the audit log is hash-chained so
  same-uid history rewriting is provable once a head is anchored
  externally.
- Issue #12: AUR `omaseal-bin` — registration portal closed; blocked on a
  human browser step when registration reopens.
- First-party Omarchy integration: `omarchy-secrets-*` commands +
  `omarchy.secrets` panel + menu entry → Discussion + PR to
  `omacom/omarchy-mac` (base `quattro`); phased fallback (commands + menu
  only) if the panel is the sticking point.
- Release automation hardened (`release.yml`).

## v0.7.0 — BrowserOS and plugin ecosystem

- BrowserOS resolves the real secret at request time, stores only the
  `omaseal://` reference. (Deferred: pending `omarchy-browser` checkout.)
- `docs/namespaces.md` conventions exercised by a real consumer.

## v1.0.0 — First-party

- Shipped as an official Omarchy keyring option (port to `omacom/omarchy`
  x86 once the omarchy-mac surface lands — the code is platform-agnostic).
- Stable API, documented `service/account` conventions, and third-party
  plugin adoption.
- First-run `manifest init` prompt. (Panel component extraction shipped in #51.)
- **Secret Service provider daemon** (shipped in #50; confinement follow-ups remain): `omaseal provider serve`
  claims `org.freedesktop.secrets` on the session bus and answers the full
  libsecret surface — `gh`, VS Code, copilot, docker credential helpers, and
  `secret-tool` store straight into the native vault with per-caller
  uid/pid/exe audit. `provider enable` installs the activation shadow that
  politely takes the name from gnome-keyring on next activation; the
  different-UID confinement track below folds into this daemon.

## Confinement (research track)

The pentest's deepest finding is architectural, not a bug: every control
lives in same-uid files and env, so a shell-capable process can write
`agent.json`/`session`/manifest or call Secret Service directly. The gates
deter agents using OmaSeal's interfaces; they cannot confine arbitrary
same-uid code. True confinement needs a different-uid policy daemon (a
setuid/polkit-brokered resolver, or sandboxed agent processes). Worth a
design spike before v1.0 if agent isolation becomes a requirement rather
than a convenience.

Partially mitigated: the audit log is hash-chained (`logs verify` /
`logs seal`), so tampered *history* is provable once a head is anchored
off the state dir — detection of rewriting, not prevention of same-uid
writes.

Native encrypted backend: **shipped and live** (#38, plus migrate #40,
key escaping #41, session hygiene #42, agent-unlock lazy-init #43).
Verified end-to-end on a real keyring: 773 items migrated, list parity,
byte-identical spot checks, rollback = one config line.

A post-flip red team exercised the same-uid surface concretely: while a
native session is live, `native-session.json` holds the ephemeral key in
plaintext and `native-session.age` re-wraps the real identity to it —
two file reads yield every store item with zero passphrase, bypassing
the CLI entirely (demonstrated 773/773). Expired session key files are
scrubbed when a later identity load detects expiry (#42) — not on a
timer — but a live session is plaintext-equivalent key material by design.
`identity.age` offline brute-force (~500 ms/guess via scrypt) remains the
only real at-rest gate once no session exists.

That hardens the case for the different-uid helper daemon — the only real
same-uid confinement: it would hold the identity in *its* memory, leaving
nothing readable on tmpfs at all. Stays a separate design track before
v1.0 if agent isolation becomes a requirement rather than a convenience.

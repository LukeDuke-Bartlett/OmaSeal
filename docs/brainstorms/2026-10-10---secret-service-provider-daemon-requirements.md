---
title: "Secret Service provider daemon — OmaSeal serves org.freedesktop.secrets"
created_at: 2026-10-10
type: feat
topic: secret-service-provider-daemon
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-brainstorm
execution: code
---

# Requirements — Secret Service provider daemon

## Goal Capsule

- **Objective:** OmaSeal implements the freedesktop Secret Service API on the
  session D-Bus so that every libsecret client — VS Code, `gh`, Electron apps,
  Agent Zero, browsers — stores into OmaSeal's vault without knowing it exists.
  This is the "first-party integration" endgame: apps already speak
  `org.freedesktop.secrets`; they never had to learn `omaseal`.
- **Product authority:** user directive 2026-10-10 — "we could maybe replace
  org.freedesktop.secrets, that would be good" — plus explicit adds:
  deterministic tests, a planned pentest program, CI/CD wiring, and a
  feasibility analysis across user environments.
- **Absorbed scope:** the different-UID helper-daemon research track folds into
  this daemon — it is the natural home for same-UID confinement hardening
  (Landlock/seccomp/ambient-authority reduction), not a second daemon.
- **Sequencing:** lands after the panel extraction and the clipboard-save
  feature; this doc is the spike's requirements input.

## Product Contract

### Problem frame

Apps that should be "using OmaSeal" today cannot see it: they call
`org.freedesktop.secrets` over D-Bus, not the `omaseal` CLI. Today that name is
owned by gnome-keyring (or KWallet's bridge, or KeePassXC), so those secrets
land outside the vault. The original report: "github vs code didnt store or see
omaseal locally, and neither did agent zero." Owning the well-known name makes
OmaSeal the destination for every libsecret client with zero per-app work.

### Requirements

**Provider surface**

- R1. Implement the `org.freedesktop.Secret` API on the session bus:
  `Service`, `Collection`, `Item`, `Session`, `Prompt` objects; `OpenSession`
  (DH-ietf1024-sha256-aes128-cbc-pkcs7, plus a deliberately decided plain
  transport policy), `SearchItems`, `Unlock`, `Lock`, `GetSecrets`,
  `ReadAlias`/`SetAlias`, item `Get`/`Set`/`Delete` with session-encrypted
  transport — enough that a stock libsecret client round-trips without knowing
  the provider changed.
- R2. Items are served from the OmaSeal vault (native store). Secret Service
  collections map onto the service/account model; `default` alias is
  supported. Existing gnome-keyring contents transition via `omaseal migrate`,
  not by the daemon proxying a competitor.
- R3. Locked-collection access produces a spec-conformant `Prompt` object that
  drives the existing masked GUI prompter stack (pinentry → zenity); agents
  and non-GUI callers get the documented fail-closed behavior, never a
  blocking dialog.
- R4. Provider contention is handled politely: detect the current name owner;
  if gnome-keyring/kwalletd/keepassxc already owns the name, refuse to squat
  and surface instructions instead of racing for it. `omaseal provider
  status|enable|disable` manages our D-Bus activation file and reports who
  currently owns the name.

**Daemon lifecycle**

- R5. Dual activation: a `org.freedesktop.secrets.service` D-Bus activation
  file for lazy startup, and a `systemd --user` unit for boot persistence and
  supervision. Idle-exit policy is a decided requirement, not an accident.
- R6. The daemon is the delivery vehicle for same-UID confinement research:
  evaluate Landlock/seccomp/ambient-capability reduction so the long-running
  holder of decrypted material is smaller than the attack surface of "any
  process at your uid". Phase 1 ships the provider without this; the design
  must not foreclose it.
- R7. CLI/MCP behavior is unchanged: `omaseal get/set/list/agent` works with
  or without the daemon running (the daemon is a serving layer, not a data
  layer).

**Deterministic testing**

- R8. A protocol conformance suite runs on a **private session bus** spawned
  per test (`dbus-daemon` fixture): our daemon claims the name on the private
  bus, a test client negotiates encrypted sessions, and spec assertions run
  event-driven (name-owner watches, prompt-completion signals) — zero sleeps,
  zero timing dependence.
- R9. `secret-tool` (a real libsecret client) round-trips store/get/delete
  against the daemon on the private bus in CI — the truest proof that first
  party works. Deterministic by construction.
- R10. Prompt paths exercise the existing stubbable prompt seams; the real
  native store runs against tmpdir fixtures — no mocking of the crypto layer.

**Pentest program (planned, not one-off)**

- R11. `docs/security/pentest-plan.md` + `pentest/` harness: each threat gets
  attack description, expected mitigation, automated-vs-manual method, and a
  severity bucket. Threat list at minimum: same-UID theft (procfs memory, env
  scraping, ptrace), D-Bus name spoofing (imposter claims the name first —
  what do clients see?), prompt hijack, tmpfs session-file exposure,
  hash-chain log tamper, unlock brute-force oracle, clipboard residue, MCP
  manifest bypass, import-path injection, session-file TOCTOU, daemon
  crash-during-write integrity.
- R12. Pentest findings land as issues tagged `pentest` — the program is a
  recurring pass per release line, not a single audit.

**CI/CD + packaging**

- R13. Protocol/conformance tests join the existing `go test` CI gate; the CI
  image gains `dbus-daemon` and `libsecret` (`secret-tool`) as declared deps.
  The pentest harness runs as a manual `workflow_dispatch` job (and locally),
  never as a flaky gate.
- R14. `release.yml` and the PKGBUILD ship the daemon binary, the D-Bus
  activation file, and the systemd user unit — installed inert until
  `omaseal provider enable`.

### Feasibility across environments (the "different situations" matrix)

- F1. **Provider contention is the crux.** Only one process may own
  `org.freedesktop.secrets`. If gnome-keyring-daemon, kwalletd6, or
  KeePassXC already claims it, we cannot serve — the daemon must detect,
  refuse, and instruct (mask the competitor's activation file) rather than
  race. Apps holding proxies to the old provider see a name-owner change;
  most libsecret clients reconnect, some cache — document.
- F2. **DE spread:** Hyprland/sway/niri users typically have no or an opt-in
  provider — cleanest win. GNOME is the hard case: gnome-keyring is woven
  into PAM auto-unlock, GCR prompts, Seahorse, Online Accounts — replacement
  must be opt-in with the breakage surface documented. KDE: kwalletd6 also
  serves the freedesktop name (same contention), while KWallet-native apps
  use a different API entirely and are unaffected.
- F3. **Flatpak/snap:** sandboxed apps reach secrets through
  `xdg-desktop-portal`'s Secret portal, whose backend is gnome-keyring today
  — they will not hit our daemon unless the portal backend is swapped or the
  app is granted `--talk-name=org.freedesktop.secrets`. Document as a
  phase-2 limitation, not a phase-1 blocker (native packages unaffected).
- F4. **Headless/SSH:** no session bus means no daemon — agents on SSH
  sessions keep using CLI/native backend unchanged. Must not regress.
- F5. **Unlock-at-login parity:** gnome-keyring auto-unlocks via PAM.
  Phase 1 accepts a first-access prompt (documented regression vs GNOME
  behavior); PAM integration is phase 2.
- F6. **Architecture/portability:** pure-Go daemon — same portability as the
  CLI; pinentry/zenity prompters already carry the cross-DE prompt story.
- F7. **Rollback must be tested:** `provider disable` removes our activation
  file and restores the previous provider on next activation — a verified
  exit ramp, not a one-way door.

### Non-goals

- KWallet's native API (separate protocol; KWallet-only apps unaffected).
- The xdg-desktop-portal Secret backend swap (phase 2).
- PAM auto-unlock module (phase 2).
- Simultaneous multi-provider shadowing (the spec names one owner).
- Replacing the CLI/native backend — the daemon is additive.

### Verified during brainstorm (do not re-derive)

- `omaseal migrate` already copies Secret Service items into the native store —
  the transition path exists today.
- The masked GUI prompter stack (`promptDesc`, pinentry→zenity order) landed
  in #47/#48 and is reusable for `Prompt` objects as-is.
- `secretservice` backend stays supported as a client of the provider — the
  daemon is additive; nothing about `backend: secretservice` breaks.

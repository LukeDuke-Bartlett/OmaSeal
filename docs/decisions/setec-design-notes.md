# setec design-read — notes

Status: **design-read output** · plan: `docs/plans/2026-10-19-001-eval-setec-design-read-plan.md`
Sources read in full at pinned revisions: `tailscale/setec@bc168fdb23` — `docs/server.md`, `docs/api.md`, plus `types/api/api.go`, `acl/acl.go`, `audit/audit.go`, `client/setec/{store,watcher,keyring}.go`, `db/kv.go`. `tailscale/tsidp@4047a40f7f` skimmed for the identity half only. Snapshot dated 2026-10-22.

## The shape of the thing

setec answers "what does secrets management look like when it's a *service*": one HTTP server (over tsnet/WireGuard), an encrypted JSON-on-disk store, tailnet-identity ACLs, versioned secrets, an append-only audit log, and a Go client with a polling cache + watcher API. Everything OmaSeal-shaped exists — but centered on *who is asking* (network identity) where OmaSeal centers on *what is being read* (per-secret manifest policy).

## Feature map

| setec feature | OmaSeal verdict | Local-first reasoning |
|---|---|---|
| Versioned secrets (`Versions` map, `ActiveVersion`, `LatestVersion`, `DeletedVersions` tombstones — `db/kv.go`) | **need** | Rollback is a real incident shape: the 2026-09-30 rekey incident showed how fast a bad write propagates. `set` overwriting the only copy means a fat-fingered `set` is unrecoverable. Local versioning costs little — append-only value list per `(service,account)` key. |
| Staged activation (`put` ≠ `activate`; `create-version` claims a never-used number; `ErrVersionClaimed` forbids reuse even after delete — `types/api/api.go`, `acl/acl.go`) | **need** | The useful half is *deliberate activation*: write v2, flip active when verified, old version still there. Version tombstones prevent a subtle replay — a deleted version number can never silently return. No need for the API split; `omaseal set` can append+activate, `omaseal activate svc acct v` flips back. |
| Conditional get (`UpdateIfChanged` + `Version` → 304 without an auditable read — `docs/api.md`) | **want** | Elegant answer to polling-vs-forensics: clients that poll for rotation don't spam the audit log with reads that found nothing. Matters once versioning exists; without versions there's nothing to poll *for*. Pair it with the versioning unit, not before. |
| Watcher/update delivery (`client/setec/watcher.go` — `Ready()` level-triggered chan; `Store` polls on `PollInterval`, cache expires by `expiryAge`) | **want** | Local equivalent isn't polling — it's notification. OmaSeal already owns the session bus; a `signal SecretChanged(service, account)` on the provider daemon gives panels/agents live invalidation for free. Cheaper and better than setec's poll loop because there's no network boundary to amortize. |
| Sealed bootstrap (access key from AWS KMS ARN, or sealed to TPM 2.0 via `--tpm-key-file`; `--dev` dummy key — `docs/server.md`) | **need, translated** | The *property* to borrow: storage key unwrap gated by something stronger than a passphrase in memory. OmaSeal's native store is age+scrypt — good, but the passphrase is the whole envelope. Translation isn't TPM (Asahi has none) — it's the different-UID helper: the helper holds the unwrapped identity, the same-UID surface gets handles, not keys. See §Implications. |
| Per-client identity ACLs (tailnet capability `tailscale.com/cap/secrets` → `acl.Rule{action, secret-pattern}` — `acl/acl.go`, `docs/server.md` grants) | **need, translated** | setec's ACL answers *who*; OmaSeal's manifest answers *what*. The strongest form combines them: `ALLOW/ASK/DENY` per secret **scoped per agent identity**. Today "who" is inferred from ppid/comm — spoofable by any same-UID process. Real per-client identity needs the different-UID boundary (kernel-checked credentials), same conclusion as sealed bootstrap. |
| Audit log with denied-attempt records (`audit/audit.go` — `Entry{ID,Time,Principal,Action,Authorized,Secret,SecretVersion}`, one JSON object per line, sync per write) | **have (better in one way, weaker in one)** | OmaSeal's `omaseal.log` is already append-only AND hash-chained (`logs verify`/`seal`) — setec's JSONL has no integrity story at all. What setec does better: `Authorized bool` on every entry makes denied-attempt forensics a first-class field, and `Principal` records *who asked*. OmaSeal logs op results but the actor field is thin — worth tightening when per-client identity lands. |
| Uniform enforcement boundary (HTTPS API only; `Sec-X-Tailscale-No-Browsers` header kills browser-originated calls — `docs/api.md`) | **interesting** | setec has exactly one door and everything passes through it. OmaSeal has three: MCP, JSON IPC, raw CLI — and the manifest only guards the first. A same-UID agent with shell access bypasses the sanctioned path today. The header trick itself doesn't translate, but the *posture* does: one enforcement point, everything else a client of it — again pointing at the helper-daemon boundary. |
| Automatic backups (`--backup-bucket` S3, timestamped, up to 1/min on change — `docs/server.md`) | **want (weak)** | `items.json.bak` + the age-encrypted store already survive crashes. Encrypted-at-rest snapshot export would help sync/restore stories (1Password sync, machine migration), but it's a convenience, not a control. |
| tsidp: OIDC + MCP-Authorization over tailnet identity (`tailscale/tsidp`, notes only) | **interesting, parked** | Relevant only if an MCP-gateway plan adopts OAuth-in-front-of-MCP. Local agents have no OIDC handshake to ride. Revisit then; nothing to borrow today. |

## What OmaSeal has that setec lacks

| OmaSeal capability | Why it matters here |
|---|---|
| `ai-manifest.txt` ALLOW/ASK/DENY per secret | Finer than setec's allow-only ACLs (action-scoped rules over wildcard secret patterns — `acl/acl.go`): the gap isn't granularity, it's that setec has no ASK tier — presence-gated reads are a local-machine luxury. |
| Same-UID agent sessions + `omaseal agent unlock` presence proof | setec assumes network identity exists; OmaSeal manufactures "who" on a single machine. Weaker cryptographically, but it's the only model that fits. |
| `ask-save` — masked OS dialog collects a human-entered secret into the store | Agents can request a credential without ever seeing it. setec's `put` flows the value through the caller. This direction (agent asks → human types → store) has no setec analog. |
| `omaseal run -e K=svc/acct` env injection, `resolve` multi-backend fan-out, `import 1password/bitwarden`, `sudo` feed | Client-side ergonomics setec deliberately doesn't own (its client is a library/cache). OmaSeal's value is *being* the local substrate, not the API. |
| Hash-chained tamper-evident log (`logs verify`, `seal` anchors) | Forensics > setec's plain JSONL: mid-history edits are detectable and chain heads can be anchored out-of-band. |
| Presence-gated `reveal` (fprintd/pinentry), panel UI | Human-presence as an auth factor — meaningless for a network service, core for a desktop keyring. |

## Implications for the different-UID daemon spike

The read converges on one conclusion: **OmaSeal's weakest properties — spoofable client identity, passphrase-held keys, a manifest with side doors — are all the same problem.** setec gets them "for free" because the server is a different *thing* than the client: kernel-enforced network identity, keys held server-side, one API surface. The local analog of that split is a different-UID helper daemon:

- **Identity** → peer credentials (`SO_PEERCRED`/`SCM_CREDENTIALS` on the IPC socket, or polkit-style checks) replace comm-name inference. Then manifest entries can legitimately gain a per-agent column.
- **Sealed bootstrap** → the helper is the KMS/TPM stand-in: it holds the unwrapped age identity in memory; clients get operation results, never key material. Lock = helper drops the identity.
- **Audit principal** → `audit.Entry.Principal` is the model once the caller is trustworthy: `{uid, exe-path-verified-pid, agent-codename}` instead of a hostname.
- **Uniform boundary** → MCP, IPC, and CLI all become clients of the helper's socket; the manifest check moves inside the helper, centralizing enforcement on one surface. Honest caveat: peer credentials *identify* the connecting process — authorizing a claimed agent identity is the spike's open question (PID reuse, executable replacement between connect and read, and what binds `agent-codename` to a verified `/proc/<pid>/exe`). The helper centralizes the check; how strong the binding is decides what centralization buys.
- **Versioning** is orthogonal and can ship before the helper — it's a native-store change (`items.json` gains a versions array + active pointer + tombstone set).

Nothing in setec argues *against* local-first; its access control is elegant precisely because Tailscale hands it identity for free. The borrow is the boundary discipline, not the network.

## Not adopted

- tsnet/WireGuard transport, TLS, LetsEncrypt — no server exists to expose.
- AWS KMS — no cloud dependency wanted; the helper-daemon model covers the property.
- setec's REST shape — OmaSeal's surfaces (D-Bus Secret Service, MCP stdio, JSON IPC, CLI) are already the right local shapes.

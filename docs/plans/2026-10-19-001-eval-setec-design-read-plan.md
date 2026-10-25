---
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan user-directed
external_source: tailscale/setec (github.com/tailscale/setec) @ bc168fdb23 (main, 2026-10-02), BSD-3, Go; + tailscale/tsidp @ 4047a40f7f (main, 2026-10-21, notes only). Snapshot metrics dated 2026-10-22: setec 485★, tsidp 685★.
---

# setec design-read — what a production secrets service does that we don't

## Goal Capsule

Read Tailscale's setec — a real secrets-management service with versioned secrets, tailnet-ACL access control, audit logging, sealed-key bootstrap (KMS/TPM), and automatic update delivery — and produce design notes on what OmaSeal should borrow. Read-for-ideas, not adoption.

## Product Contract

### The comparison that matters

OmaSeal is local-first: `omaseal get/set` against a local keyring with a manifest policy (`ai-manifest.txt` — ALLOW/ASK/DENY per secret) and agent sessions. The policy boundary is narrower than it looks: the manifest and agent trust modes govern only the MCP/agent channel — the CLI and JSON IPC are trusted local surfaces that bypass it, and an agent with unrestricted shell access can reach the raw CLI and skip the sanctioned agent path entirely. setec is a *service*: secrets live server-side, clients fetch over WireGuard-encrypted HTTP at runtime, access scoped by tailnet identity + ACL document — its ACL is the *only* boundary and it is enforced uniformly. Different center of gravity — which is exactly why it's worth reading: it answers "what does the server-side version of this look like?"

### The features to evaluate borrowing

- **Versioned secrets**: each secret is a named collection of versioned values; `get` can pin a version or take active. (Does OmaSeal version? If not — should it? Rollback story.)
- **Activation/deactivation windows**: staged rotation — new version added, activated later, old retired. (OmaSeal rotation = `set` again; setec's is more deliberate.)
- **Audit log of accesses**: every read recorded server-side. (OmaSeal has `omaseal_stats` access counts — setec's is forensics-grade.)
- **Sealed bootstrap**: server's storage key sealed to KMS/TPM — secrets-at-rest story beyond "it's the keyring."
- **Identity-scoped access**: ACL by *who is asking* (tailnet identity), not just *what is being read* (manifest policy). OmaSeal's manifest is per-secret; setec adds per-client.
- **tsidp adjacent note**: tsidp adds OIDC + MCP-Authorization-spec flows on tailnet identity — the identity half of this story. Revisit if the MCP-gateway plan adopts OAuth-in-front-of-MCP.

### Scope boundaries

- **In:** read server docs + API doc, write `docs/decisions/setec-design-notes.md` with a borrow/interesting/n-a table.
- **Out:** running a setec server, changing OmaSeal's architecture, adopting tsidp.

### Requirements

1. Read `server.md` + `api.md` fully; the secret-versioning + activation semantics are the highest-value read.
2. For each feature above: does OmaSeal have it, need it, or explicitly not want it (local-first vs service is a real philosophical fork — version where honestly).
3. Note what OmaSeal has that setec lacks (manifest ALLOW/ASK/DENY policy — finer than setec's all-or-ACL).
4. Output the notes doc with concrete "if we add X it should look like their Y" pointers.

### Acceptance examples

- The notes doc lists every setec feature and maps it: have/need/want — no item left unevaluated.
- The notes cite coverage of both `server.md` and `api.md` in full, not a skim of the README.
- Every "borrow" row carries a concrete `if we add X it should look like their Y` pointer (file/doc/mechanism), per Requirement 4.
- A reciprocal table lists OmaSeal capabilities setec lacks (e.g. manifest ALLOW/ASK/DENY, same-UID agent sessions), per Requirement 3.
- Each verdict states the local-first reasoning honestly — a "not wanted" with rationale counts as evaluated, per Requirement 2 and the scope boundary that no architecture change is being adopted.

## Repo Touchpoints

- `docs/decisions/setec-design-notes.md` (new)
- `engine/` referenced in notes where a borrowed pattern would land

## Test Scenarios

None — design-read artifact.

## Risks / Honest Notes

- setec assumes a tailnet — its access-control elegance *is* Tailscale. Anything borrowed must translate to OmaSeal's local-first model or it's a category error.
- 484★, quiet repo (3 open issues, monthly pushes) — stable, finished, low-drama. That's a feature for a reference read.

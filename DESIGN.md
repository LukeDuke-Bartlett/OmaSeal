# Design direction: Strongroom

Status: proposal. Method: the `refero-design` research-first method (reference lock, decision ledger, anti-slop gate). The Refero MCP was not available in this session, so no new external references were fetched; the references are the Omarchy shell kit, the existing panel (`screenshot.png`) and macOS Keychain Access, which the README already names as the model.

Scope: panel (`Panel.qml`), bar widget (`BarWidget.qml`), CLI output, README. No change to crypto, unlock, manifest or IPC code.

## 1. Direction

**Name: Strongroom.** A secrets panel should feel sealed and plain: dense monospace rows, one accent, and loud only when protection is weakened. Calm by default, unmistakable when a gate is off.

Memorable detail: secret values are never shown in the panel at all; rows show `service / account` and a usage badge. Absence is the design.

## 2. Reference lock

```text
Primary direction: the Omarchy shell kit (Color, Style, Button, PanelSectionHeader).
Preserve: theme colours only, Style.cornerRadius, bar font family, keyboard-first list (j/k, /, v, s, Enter, x, e).
Borrow only: Keychain Access's "one list, attributes beside the name" (README names it as the model).
Role rules: accent = unlocked / open agent state and notices; urgent = failures and any
  state where protection is weakened (ungated unlock); dim = everything else.
Reject: lock emoji in UI or marketing, padlock-and-key clip art, green "secure" badges,
  hardcoded hex, animations on secret rows.
```

## 3. Decision ledger

| Decision | Role | Why |
|---|---|---|
| Colours from `Color.*`; no fallback hex | theme owns palette | the urgent fallback was a fixed pink; now the accent |
| Ungated-unlock notice in urgent | state | weakened protection must not look like a hint |
| Agent trust line stays accent when open or unlocked, dim otherwise | state | existing behaviour, kept |
| Keyhole mark, geometric | identity | one idea: a keyhole is what a keyring has, no clip art |
| Social card without emoji | marketing | existing `docs/assets/social.png` uses a padlock emoji |

## 4. Tokens

Panel tokens are the theme's: text `fg`, secondary `dim = Qt.darker(fg, 1.5)`, `accent`, `urgent`. Contrast is the theme's responsibility; I did not compute ratios across themes. One check to make on light themes: `Qt.darker(fg, 1.5)` of a dark foreground is darker, so secondary text gains contrast there; on dark themes it drops fg to about 67 percent brightness (white to `#aaaaaa`, about 9:1 on black), fine. Static brand colours and ratios: `assets/brand/README.md`.

Type: bar font family at `Style.font.caption` for hints and badges. Section headers upper-case (`SECRETS`, `VAULTS`).

## 5. Icon and glyph style

Nerd Font glyph for the key (`󰌋`) in the bar and panel; the brand keyhole is for README and listing only. Provider and vault badges are text, not icons.

## 6. Motion

None on secret rows. Clipboard clear after 30 s is silent by design; the notice line reports it.

## 7. Surfaces

| Surface | File |
|---|---|
| Bar widget | `BarWidget.qml` |
| Panel: vault sidebar, secret list, add form, agent trust line, logs page | `Panel.qml` |
| CLI output (`doctor`, `stats`, `mcp status`) | `engine/` (text only; not touched here) |
| README, social card | `README.md`, `assets/brand/` |

## 8. Anti-slop gate

No emoji icons in the product: pass (`docs/assets/social.png` is the exception, replaced by `assets/brand/social-card.svg`). No decorative "secure" colour: pass. No default indigo: pass.

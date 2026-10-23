# Brand assets (proposal)

**Status: proposal.** The owner signs off logos. Nothing here changes the plugin, which takes colours from the user's Omarchy theme.

## Construction

A rounded square outline (radius 8, 4 px stroke) holding a keyhole built from one circle (r 8) and one trapezoid, in the accent colour. All geometry is on a 64 px grid with straight edges, matching the Omarchy shell's flat chrome; it reads at 16 px (`preview/logo-16.png`).

## Files

| File | Use |
|---|---|
| `logo.svg`, `logo-dark.svg` | mark on light and dark grounds |
| `wordmark.svg`, `wordmark-dark.svg` | mark plus "OmaSeal" (live `<text>`, monospace stack, not outlined) |
| `social-card.svg` | replaces `docs/assets/social.png`, which uses a lock-and-key emoji |
| `preview/` | PNG renders from `resvg` |

## Colours (static, for README and listing use only)

| Variant | Ink | Accent | Accent contrast |
|---|---|---|---|
| light | `#1c1b18` | `#0f766e` | about 5.5:1 on `#ffffff` |
| dark | `#e8e6df` | `#5eead4` | about 13:1 on `#0d1117` |

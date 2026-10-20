#!/bin/bash
# Static guards for the secrets panel refactor — runs in CI and locally.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "check-panel: FAIL — $*" >&2; exit 1; }

# 1. The plaintext buffer is gone: no getText property anywhere in the plugin.
! grep -rn "getText" --include='*.qml' . || fail "getText property still present"

# 2. Boundary contract names still present in Panel.qml, anchored to
#    declaration syntax so a usage or comment can't satisfy them.
for name in "signal statusChanged" "function open" "function close" \
            "function toggle" "function closeForPopoutSwitch" \
            "function switchPanel" "property var anchorItem" \
            "property var hostWidget" "property var settings" \
            "property bool popoutSwitchClosing"; do
  grep -qF "$name" Panel.qml || fail "Panel.qml is missing '$name'"
done

# 3. Plugin .qml files match every packaging surface's file list exactly — a
#    new sibling file that misses any of them ships a broken panel.
qml_files=$(ls ./*.qml | sed 's|^\./||' | sort)
for surface in .github/workflows/release.yml .github/workflows/ci.yml \
               Makefile packaging/aur/PKGBUILD packaging/aur/PKGBUILD-bin; do
  surface_files=$(grep -o '[A-Za-z0-9_-]*\.qml' "$surface" | sort -u)
  [[ "$qml_files" == "$surface_files" ]] || fail ".qml files differ from $surface file list:
$(diff <(echo "$qml_files") <(echo "$surface_files"))"
done

# 4. No Process collects omaseal get stdout into QML — the copy path pipes get
#    directly into wl-copy and never assigns output to a property.
! grep -rnE '"omaseal"[[:space:]]*,[[:space:]]*"get"' --include='*.qml' . || fail "a Process still captures omaseal get stdout"
grep -qF 'omaseal get "$1" "$2"' PanelJobs.qml || fail "positional omaseal get | wl-copy pipeline missing"
grep -qF 'printf %s "$out" | wl-copy --sensitive' PanelJobs.qml || fail "wl-copy --sensitive pipeline missing"

# 5. Injected cross-file names are declared in their owning files. QML resolves
#    these lazily at runtime — a rename compiles clean and degrades silently.
for decl in "property var secretsModel" "property var logModel" \
            "function applyList" "function applyLogs" "function rebuildModel" \
            "function secretKey" "function ago" "function cycleSort" \
            "function sortLabel" "signal noticeSet"; do
  grep -qF "$decl" PanelModel.qml || fail "PanelModel.qml is missing '$decl'"
done
for decl in "function clearPass" "function focusPass" "signal unlockRequested"; do
  grep -qF "$decl" AgentSection.qml || fail "AgentSection.qml is missing '$decl'"
done
for decl in "function copySecret" "function deleteSecret" "function saveSecret" \
            "function unlockAgent" "function refresh" "function refreshLog" \
            "function refreshAgentStatus" "function cancelArmedDelete" \
            "property bool unlockRunning" "signal noticeSet" \
            "signal dataChanged" "signal saved" "property var model" \
            "property var agentView"; do
  grep -qF "$decl" PanelJobs.qml || fail "PanelJobs.qml is missing '$decl'"
done
for decl in "signal copyRequested" "signal deleteRequested" "signal rowEntered" \
            "function submit" "function clear" "function dismiss"; do
  grep -qE "$decl" SecretsView.qml AddEditForm.qml || fail "view layer is missing '$decl'"
done

# 6. Parse check (best-effort): every sibling must at least parse — the file
#    lists above can't see a sibling that fails to instantiate. qmllint's
#    [syntax] category catches it independent of the unresolvable qs.* imports.
qmllint=$(command -v qmllint || true)
[ -z "$qmllint" ] && [ -x /usr/lib/qt6/bin/qmllint ] && qmllint=/usr/lib/qt6/bin/qmllint
if [ -n "$qmllint" ]; then
  for f in ./*.qml; do
    # Not a `qmllint | grep -q` pipeline: under pipefail, grep -q's early exit
    # SIGPIPEs qmllint and the pipeline can return nonzero — silently passing.
    lint_out=$("$qmllint" "$f" 2>&1 || true)
    grep -q '\[syntax\]' <<< "$lint_out" && fail "qmllint syntax error in $f"
  done
else
  fail "qmllint is required for the panel syntax check (qt6-declarative tools)"
fi

echo "check-panel: PASS"

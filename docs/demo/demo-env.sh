#!/usr/bin/env bash
# Throwaway sandbox for recording docs/demo/omaseal.tape: a scratch HOME, an
# unlocked scratch keyring, and fake "DEMO-NOT-A-KEY" values. Nothing real is read.
#
#   dbus-run-session -- docs/demo/demo-env.sh vhs docs/demo/omaseal.tape
#
# Needs `omaseal` on PATH (e.g. ln -sf "$PWD/engine/omaseal" /usr/local/bin/omaseal
# in a scratch dir that you put first on PATH).
set -euo pipefail
export HOME="$(mktemp -d)"
export XDG_RUNTIME_DIR="$HOME/rt" XDG_CONFIG_HOME="$HOME/c" XDG_DATA_HOME="$HOME/d" XDG_STATE_HOME="$HOME/s"
mkdir -p "$XDG_RUNTIME_DIR" "$HOME/.local/share/keyrings" "$HOME/.hermes" "$XDG_CONFIG_HOME/omaseal" "$XDG_STATE_HOME/omaseal"
chmod 700 -R "$XDG_RUNTIME_DIR" "$HOME/.local"
echo demo | gnome-keyring-daemon --unlock >/dev/null
unset NO_COLOR FORCE_COLOR
echo "model: demo" > "$HOME/.hermes/config.yaml"
printf 'DEMO-NOT-A-KEY-1' | omaseal set openrouter default >/dev/null 2>&1
printf 'DEMO-NOT-A-KEY-2' | omaseal set github token >/dev/null 2>&1
printf 'DEMO-NOT-A-KEY-3' | omaseal set sales-metrics prod-db-url >/dev/null 2>&1
for _ in 1 2 3; do omaseal get openrouter default >/dev/null 2>&1; done
omaseal get github token >/dev/null 2>&1
exec "$@"

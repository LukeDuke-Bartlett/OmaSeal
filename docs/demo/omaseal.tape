# OmaSeal CLI demo — records docs/demo/omaseal.gif.
#
#   dbus-run-session -- docs/demo/demo-env.sh vhs docs/demo/omaseal.tape
#
# demo-env.sh builds a throwaway HOME + keyring with fake values and needs
# `omaseal` on PATH; nothing real is read.

Output docs/demo/omaseal.gif

Require omaseal

Set Shell "bash"
Set FontSize 15
Set Width 1100
Set Height 760
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set WindowBar Colorful

Hide
Type "export PS1='$ '; clear" Enter
Show

Type "omaseal" Enter
Sleep 4s
Ctrl+L

Type "omaseal ls --sort=used" Enter
Sleep 3s

Type "omaseal get github token | wc -c   # raw value to stdout, never decorated" Enter
Sleep 2500ms
Ctrl+L

Type "omaseal rm github token" Enter
Sleep 1500ms
Ctrl+L

Type "omaseal mcp install hermes && omaseal mcp status" Enter
Sleep 4s
Ctrl+L

Type "omaseal agent mode --help" Enter
Sleep 4s

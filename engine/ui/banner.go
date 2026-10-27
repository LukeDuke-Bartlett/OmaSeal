package ui

import (
	"fmt"
	"io"
	"strings"
)

// The keyhole mark from assets/brand/logo.svg — a rounded square holding a
// keyhole (circle over a trapezoid) — redrawn in block characters.
var mark = []string{
	"╭─────╮",
	"│ ▄█▄ │",
	"│ ▀█▀ │",
	"│ ▟█▙ │",
	"╰─────╯",
}

// Banner draws the mark, wordmark and a version line to w. It is a no-op
// unless w is an interactive terminal, so it can never reach a pipe, a log,
// an MCP stdio stream or a plugin.
func Banner(w io.Writer, version, target string) {
	if !Fancy(w) {
		return
	}
	text := []string{
		"",
		Accent(w, "OmaSeal"),
		Dim(w, "keys for your agents, kept in your keyring"),
		Dim(w, fmt.Sprintf("%s · %s", version, target)),
		"",
	}
	var b strings.Builder
	for i, m := range mark {
		if text[i] == "" {
			fmt.Fprintf(&b, "%s\n", Accent(w, m))
			continue
		}
		fmt.Fprintf(&b, "%s   %s\n", Accent(w, m), text[i])
	}
	write(w, b.String())
}

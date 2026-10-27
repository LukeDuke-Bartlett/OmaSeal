// Package ui is OmaSeal's terminal presentation layer: status lines, tables,
// the banner and confirmation prompts.
//
// Two rules keep it safe to put in front of a secrets tool:
//
//  1. Decoration only ever appears when the destination is an interactive
//     terminal. Anything piped, redirected or captured (plugins, MCP clients,
//     scripts, $(...)) gets the exact plain text the pre-ui CLI produced.
//  2. Secret values never pass through this package. Callers print them raw.
//
// Colour follows https://no-color.org: NO_COLOR (non-empty) and TERM=dumb
// switch every escape sequence off while keeping the layout. Colours are
// ANSI palette indexes rather than fixed RGB, so they follow the user's
// terminal theme (Omarchy themes included) on light and dark backgrounds
// alike, with no background probing.
package ui

import (
	"io"
	"os"

	"golang.org/x/term"
)

// IsTTY reports whether w is an interactive terminal.
func IsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// Fancy reports whether w may receive decorated output (glyphs, boxes,
// tables): an interactive terminal that is not TERM=dumb.
func Fancy(w io.Writer) bool {
	return IsTTY(w) && os.Getenv("TERM") != "dumb"
}

// Color reports whether w may receive ANSI colour sequences.
func Color(w io.Writer) bool {
	return Fancy(w) && os.Getenv("NO_COLOR") == ""
}

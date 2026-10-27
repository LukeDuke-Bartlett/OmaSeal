package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
)

// Palette uses ANSI indexes so it adapts to the terminal's own theme.
var (
	accent = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	okSt   = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	warnSt = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	errSt  = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	dimSt  = lipgloss.NewStyle().Faint(true)
	headSt = lipgloss.NewStyle().Bold(true)
)

// Glyphs of the status vocabulary.
const (
	GlyphOK   = "✓"
	GlyphWarn = "!"
	GlyphErr  = "✗"
	GlyphInfo = "·"
)

// paint renders s in style st when w accepts colour, else returns s as is.
func paint(w io.Writer, st lipgloss.Style, s string) string {
	if !Color(w) {
		return s
	}
	return st.Render(s)
}

// Write prints s to w, downgrading colour to the terminal's capability.
func write(w io.Writer, s string) {
	if Color(w) {
		_, _ = lipgloss.Fprint(w, s)
		return
	}
	_, _ = io.WriteString(w, s)
}

// Dim styles secondary text (hints, paths) when w accepts colour.
func Dim(w io.Writer, s string) string { return paint(w, dimSt, s) }

// Accent styles highlighted text when w accepts colour.
func Accent(w io.Writer, s string) string { return paint(w, accent, s) }

// Status prints one status line "<glyph> <msg>" to w. On a non-terminal it
// prints msg alone, so a redirected stream matches the pre-ui plain text.
func status(w io.Writer, glyph string, st lipgloss.Style, msg string) {
	if !Fancy(w) {
		fmt.Fprintln(w, msg)
		return
	}
	write(w, paint(w, st, glyph)+" "+msg+"\n")
}

// OK prints a success line to stderr: "✓ saved sales/db".
func OK(msg string) { status(os.Stderr, GlyphOK, okSt, msg) }

// Warn prints a warning line to stderr: "! agent mode is open".
func Warn(msg string) { status(os.Stderr, GlyphWarn, warnSt, msg) }

// Fail prints a failure line to stderr: "✗ not found".
func Fail(msg string) { status(os.Stderr, GlyphErr, errSt, msg) }

// Info prints a neutral line to stderr.
func Info(msg string) { status(os.Stderr, GlyphInfo, dimSt, msg) }

// Hint prints an indented, dimmed follow-up line to stderr (a next step).
func Hint(msg string) {
	if !Fancy(os.Stderr) {
		fmt.Fprintln(os.Stderr, msg)
		return
	}
	write(os.Stderr, "  "+paint(os.Stderr, dimSt, msg)+"\n")
}

// Done reports a completed action. On an interactive stdout it prints the
// styled status line to stderr (pretty text stays on stderr); otherwise it
// prints plain on stdout so scripts keep reading the same word.
func Done(plain, pretty string) {
	if Fancy(os.Stdout) {
		OK(pretty)
		return
	}
	fmt.Println(plain)
}

// Heading prints a section heading to w.
func Heading(w io.Writer, s string) {
	if !Fancy(w) {
		fmt.Fprintln(w, s)
		return
	}
	write(w, paint(w, headSt, s)+"\n")
}

// Mark returns the glyph for a doctor-style verdict: ok, warn or fail.
// Plain output keeps the historic words.
func Mark(w io.Writer, verdict string) string {
	if !Fancy(w) {
		return verdict
	}
	switch verdict {
	case "ok":
		return paint(w, okSt, GlyphOK)
	case "warn":
		return paint(w, warnSt, GlyphWarn)
	default:
		return paint(w, errSt, GlyphErr)
	}
}

// Indent prefixes every line of s with n spaces.
func Indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// Say prints a success line to stderr only on an interactive terminal. It is
// for actions that have always been silent on success: scripts, plugins and
// logs keep seeing nothing.
func Say(msg string) {
	if Fancy(os.Stderr) {
		OK(msg)
	}
}

package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/huh/v2"
)

// Confirm asks a yes/no question and returns true only on an explicit yes.
// The default answer is always No: pressing Enter, EOF, Ctrl-C or any
// unreadable input declines.
//
// With an interactive stdin and stderr it shows a huh prompt on stderr.
// Otherwise (scripts, CI, tests) it reads one line from in and accepts only
// "y" or "yes". Prompts are written to stderr, never stdout.
func Confirm(question string, in *bufio.Reader) bool {
	if IsTTY(os.Stdin) && Fancy(os.Stderr) {
		var yes bool
		form := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().
				Title(question).
				Affirmative("Yes").
				Negative("No").
				Value(&yes),
		)).WithOutput(os.Stderr)
		if err := form.Run(); err != nil {
			return false
		}
		return yes
	}
	return ConfirmLine(os.Stderr, in, question+" [y/N] ")
}

// ConfirmLine writes prompt to out and reads one line from in; only an
// explicit y/yes accepts.
func ConfirmLine(out io.Writer, in *bufio.Reader, prompt string) bool {
	fmt.Fprint(out, prompt)
	text, err := in.ReadString('\n')
	if err != nil {
		fmt.Fprintf(out, "  could not read response: %v\n", err)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "y", "yes":
		return true
	}
	return false
}

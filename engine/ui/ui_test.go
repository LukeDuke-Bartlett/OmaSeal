//go:build linux

package ui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"text/tabwriter"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY returns the slave side of a fresh pseudo-terminal, so tests can
// exercise the "interactive terminal" branch without a real terminal. The
// master side is drained in the background so writes never block.
func openPTY(t *testing.T) (slave *os.File, output func() string) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	var unlock int32
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, master.Fd(), unix.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Skipf("TIOCSPTLCK: %v", e)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("TIOCGPTN: %v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open pts: %v", err)
	}
	t.Cleanup(func() { slave.Close(); master.Close() })
	fd := int(master.Fd())
	return slave, func() string {
		// Writes to the slave are delivered synchronously; read whatever the
		// line discipline has queued without blocking.
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatalf("SetNonblock: %v", err)
		}
		var out bytes.Buffer
		buf := make([]byte, 4096)
		for {
			n, err := unix.Read(fd, buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if err != nil || n <= 0 {
				break
			}
		}
		return out.String()
	}
}

func TestNonTerminalWritersNeverGetDecoration(t *testing.T) {
	var b bytes.Buffer
	if IsTTY(&b) || Fancy(&b) || Color(&b) {
		t.Fatal("a bytes.Buffer must not look like a terminal")
	}
	f, _ := os.CreateTemp(t.TempDir(), "x")
	defer f.Close()
	if IsTTY(f) || Fancy(f) || Color(f) {
		t.Fatal("a regular file must not look like a terminal")
	}
}

func TestPlainTableMatchesTabwriterByteForByte(t *testing.T) {
	headers := []string{"SERVICE", "ACCOUNT", "LABEL"}
	rows := [][]string{
		{"openrouter", "default", "OpenRouter key"},
		{"gh", "a-very-long-account-name", ""},
		{"x", "y", "z"},
	}
	for _, pad := range []int{2, 3} {
		var want bytes.Buffer
		tw := tabwriter.NewWriter(&want, 0, 0, pad, ' ', 0)
		fmt.Fprintln(tw, "SERVICE\tACCOUNT\tLABEL")
		for _, r := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r[0], r[1], r[2])
		}
		tw.Flush()

		var got bytes.Buffer
		Table(&got, pad, headers, rows)
		if got.String() != want.String() {
			t.Errorf("pad %d: plain table drifted from the historic tabwriter output\nwant %q\ngot  %q", pad, want.String(), got.String())
		}
	}
}

func TestStatusHelpersPlainOnNonTerminal(t *testing.T) {
	// Done on a non-terminal stdout prints the historic plain word.
	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	Done("ok", "saved a/b")
	w.Close()
	os.Stdout = oldOut
	got, _ := io.ReadAll(r)
	if string(got) != "ok\n" {
		t.Errorf("Done on a pipe = %q, want %q", got, "ok\n")
	}

	// Say stays silent off a terminal (it is for actions that were silent).
	oldErr := os.Stderr
	r, w, _ = os.Pipe()
	os.Stderr = w
	Say("hello")
	OK("fine")
	w.Close()
	os.Stderr = oldErr
	got, _ = io.ReadAll(r)
	if strings.Contains(string(got), "hello") {
		t.Errorf("Say wrote to a non-terminal stderr: %q", got)
	}
	if strings.Contains(string(got), "\x1b[") || strings.Contains(string(got), GlyphOK) {
		t.Errorf("OK decorated a non-terminal stderr: %q", got)
	}
}

func TestBannerSilentOffTerminal(t *testing.T) {
	var b bytes.Buffer
	Banner(&b, "v1", "linux/amd64")
	if b.Len() != 0 {
		t.Fatalf("Banner wrote to a non-terminal: %q", b.String())
	}
}

func TestTerminalDecorationAndNoColor(t *testing.T) {
	slave, out := openPTY(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	if !IsTTY(slave) || !Fancy(slave) || !Color(slave) {
		t.Fatalf("pty should be a coloured terminal: tty=%v fancy=%v color=%v", IsTTY(slave), Fancy(slave), Color(slave))
	}

	t.Setenv("NO_COLOR", "1")
	if !Fancy(slave) || Color(slave) {
		t.Fatal("NO_COLOR must keep layout but drop colour")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if Fancy(slave) || Color(slave) {
		t.Fatal("TERM=dumb must disable decoration")
	}

	// NO_COLOR table: boxed layout, zero escape sequences.
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	Table(slave, 2, []string{"A", "B"}, [][]string{{"one", "two"}})
	Banner(slave, "v1", "linux/amd64")
	got := out()
	if strings.Contains(got, "\x1b[") {
		t.Errorf("NO_COLOR output contains escape sequences: %q", got)
	}
	for _, want := range []string{"one", "two", "OmaSeal", "╭"} {
		if !strings.Contains(got, want) {
			t.Errorf("terminal output missing %q:\n%s", want, got)
		}
	}
}

func TestConfirmLineDefaultsToNo(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"\n", false}, // Enter = No
		{"", false},   // EOF = No
		{"n\n", false},
		{"no\n", false},
		{"maybe\n", false},
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{" YES \n", true},
	}
	for _, c := range cases {
		var out bytes.Buffer
		got := ConfirmLine(&out, bufio.NewReader(strings.NewReader(c.in)), "Proceed? [y/N] ")
		if got != c.want {
			t.Errorf("ConfirmLine(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestConfirmOffTerminalUsesLineReader(t *testing.T) {
	// go test has no tty on stdin, so Confirm must take the line path and
	// treat Enter as No.
	if IsTTY(os.Stdin) {
		t.Skip("stdin is a terminal")
	}
	if Confirm("Proceed?", bufio.NewReader(strings.NewReader("\n"))) {
		t.Error("Enter must decline")
	}
	if !Confirm("Proceed?", bufio.NewReader(strings.NewReader("y\n"))) {
		t.Error("y must accept")
	}
}

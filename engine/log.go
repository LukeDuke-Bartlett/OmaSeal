package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/duketopceo/OmaSeal/engine/ui"
)

var (
	logInitOnce sync.Once
	logFile     *os.File
	logFilePath string
	logWriter   io.Writer
	logInitErr  error
)

// LogPath returns the resolved path to the omaseal log file, creating the
// parent directory if needed. It is safe to call before the log file is opened.
func LogPath() string {
	logInitOnce.Do(initLog)
	return logFilePath
}

func ensureLogDir() (string, error) {
	base := svcXDGDir("XDG_STATE_HOME", ".local", "state")
	if base == "" {
		return "", fmt.Errorf("no home dir for log fallback")
	}
	dir := filepath.Join(base, "omaseal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// logMaxBytes caps the append-only log so ParseAccessLogs and ReadLog stay
// fast over the tool's lifetime. When the cap is crossed the file is
// truncated to its newest half.
const logMaxBytes = 512 * 1024

func initLog() {
	dir, err := ensureLogDir()
	if err != nil {
		logInitErr = err
		logWriter = os.Stderr
		return
	}
	logFilePath = filepath.Join(dir, "omaseal.log")
	truncateLogIfLarge(logFilePath)
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		logInitErr = err
		logWriter = os.Stderr
		return
	}
	logFile = f
	// The file half of the writer is hash-chained (engine/chain.go): each
	// line carries the sha256 of its predecessor's chain value + content, so
	// mid-history edits break `omaseal logs verify`. stderr stays unchained.
	chained := newChainWriter(logFile, logFilePath, filepath.Join(dir, "omaseal.chain"))
	// The stderr mirror is for pipes and captured output. On an interactive
	// terminal it only interleaves timestamped audit lines with the command's
	// own output, so it is dropped there; the file copy is unchanged.
	// OMASEAL_LOG_STDERR=1 brings the mirror back.
	if ui.Fancy(os.Stderr) && os.Getenv("OMASEAL_LOG_STDERR") != "1" {
		logWriter = chained
		return
	}
	logWriter = io.MultiWriter(os.Stderr, chained)
}

// truncateLogIfLarge keeps only the newest half of the log once it passes
// logMaxBytes. The retained tail starts at a line boundary.
func truncateLogIfLarge(path string) {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= logMaxBytes {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	keep := int64(logMaxBytes / 2)
	buf := make([]byte, keep)
	if _, err := f.ReadAt(buf, info.Size()-keep); err != nil && err != io.EOF {
		f.Close()
		return
	}
	f.Close()
	// Drop the first partial line.
	if i := strings.IndexByte(string(buf), '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	_ = os.WriteFile(path, buf, 0o600)
}

// LogWriter returns the multi-writer used by OmaSeal. It initializes the log
// file on first call and falls back to stderr if initialization fails.
func LogWriter() io.Writer {
	logInitOnce.Do(initLog)
	return logWriter
}

// SetLogOutput redirects the standard log package to write to both stderr and
// the omaseal log file. Call once near process start.
func SetLogOutput() {
	log.SetOutput(LogWriter())
}

// WriteLog records a single event without secret values. String arguments
// are sanitized so a caller-controlled service/account name cannot forge
// extra log lines.
func WriteLog(format string, v ...any) {
	for i, arg := range v {
		if s, ok := arg.(string); ok {
			s = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return ' '
				}
				return r
			}, s)
			// Bound field length: an unbounded foreign service/account name
			// must not write a line so large it breaks log parsing.
			if len(s) > 512 {
				s = s[:512] + "…"
			}
			v[i] = s
		}
	}
	log.Printf(format, v...)
}

// ReadLog returns the last n lines from the omaseal log file. If the file
// does not exist, it returns an empty slice.
func ReadLog(n int) ([]string, error) {
	if n <= 0 {
		n = 50
	}
	path := LogPath()
	if path == "" {
		return nil, fmt.Errorf("cannot determine log path: %v", logInitErr)
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	lines := make([]string, 0, n)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// LogLine is a structured log entry for the panel UI.
type LogLine struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	Message string `json:"message"`
}

var logLineRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.+?):\s+(.*)$`)

// ReadLogJSON returns the last n log lines as structured objects.
func ReadLogJSON(n int) ([]LogLine, error) {
	lines, err := ReadLog(n)
	if err != nil {
		return nil, err
	}
	out := make([]LogLine, 0, len(lines))
	for _, l := range lines {
		l, _, _ = chainTail(l) // drop the trailing ` chain=<hex>` field
		m := logLineRe.FindStringSubmatch(l)
		if m == nil {
			out = append(out, LogLine{Message: l})
			continue
		}
		out = append(out, LogLine{Time: m[1], Source: m[2], Message: m[3]})
	}
	return out, nil
}

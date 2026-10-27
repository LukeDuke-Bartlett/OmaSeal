package ui

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

// Table writes rows under headers to w.
//
// On a terminal it draws a rounded lipgloss table with a bold header. On
// anything else it writes the exact tabwriter layout the CLI has always used
// (minwidth 0, tabwidth 0, the given padding, space padding), so parsers of
// the plain text see no change. Cells must already be sanitized by the caller.
func Table(w io.Writer, pad int, headers []string, rows [][]string) {
	if !Fancy(w) {
		plainTable(w, pad, headers, rows)
		return
	}
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			st := lipgloss.NewStyle().Padding(0, 1)
			if !Color(w) {
				return st // NO_COLOR / dumb: layout only, no escape sequences at all
			}
			if row == table.HeaderRow {
				return st.Foreground(lipgloss.Color("6")).Bold(true)
			}
			return st
		})
	if Color(w) {
		t = t.BorderStyle(lipgloss.NewStyle().Faint(true))
	}
	write(w, t.String()+"\n")
}

func plainTable(w io.Writer, pad int, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, pad, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	_ = tw.Flush()
}

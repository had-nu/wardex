// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
	"io"
	"strings"
)

type row struct {
	cols []string
	fg   []string
	bg   []string
}

// Table builds fixed-width coloured tables for terminal output
// and pipe-delimited tables for piped / file output.
type Table struct {
	headers []string
	widths  []int
	rows    []row
}

// NewTable creates a table with the given header names and column widths.
func NewTable(headers []string, widths []int) *Table {
	return &Table{headers: headers, widths: widths}
}

// AddRow appends a plain (uncolored) data row.
func (t *Table) AddRow(cols ...string) {
	t.rows = append(t.rows, row{cols: cols})
}

// AddRowColor appends a row with per-column text colours.
// fg[i] is the ANSI colour code for column i; use "" for no colour.
func (t *Table) AddRowColor(cols []string, fg []string) {
	t.rows = append(t.rows, row{cols: cols, fg: fg})
}

// AddRowBg appends a row with per-column background colours (badges).
// bg[i] is the ANSI background code for column i; the text is rendered bright white.
func (t *Table) AddRowBg(cols []string, bg []string) {
	t.rows = append(t.rows, row{cols: cols, bg: bg})
}

// AddRowStyled appends a row with both per-column text colours and background colours.
// bg takes precedence over fg when both are set for the same column.
// Pass nil or empty slices for columns that should remain plain.
func (t *Table) AddRowStyled(cols []string, fg, bg []string) {
	t.rows = append(t.rows, row{cols: cols, fg: fg, bg: bg})
}

// RenderTTY writes the table to w with ANSI colours and fixed-width columns.

// RenderTTY writes the table to w with ANSI colours and fixed-width columns.
func (t *Table) RenderTTY(w io.Writer) {
	// header
	for i, h := range t.headers {
		if i > 0 {
			fmt.Fprint(w, "  ")
		}
		fmt.Fprint(w, PadANSI(Colorize(h, Cyan+Bold), t.widths[i]))
	}
	fmt.Fprintln(w)

	// separator
	for i, wdt := range t.widths {
		if i > 0 {
			fmt.Fprint(w, "  ")
		}
		fmt.Fprint(w, Colorize(strings.Repeat("─", wdt), Gray))
	}
	fmt.Fprintln(w)

	// data rows
	for _, r := range t.rows {
		for i, col := range r.cols {
			if i > 0 {
				fmt.Fprint(w, "  ")
			}
			v := col
			if i < len(r.bg) && r.bg[i] != "" {
				v = Colorize(v, r.bg[i]+BgText)
			} else if i < len(r.fg) && r.fg[i] != "" {
				v = Colorize(v, r.fg[i])
			}
			fmt.Fprint(w, PadANSI(v, t.widths[i]))
		}
		fmt.Fprintln(w)
	}
}

// RenderMarkdown writes the table to w as a pipe-delimited markdown table.
func (t *Table) RenderMarkdown(w io.Writer) {
	seps := func() string {
		return strings.Repeat("-", max(3, t.widths[0]))
	}
	fmt.Fprint(w, "|")
	for _, h := range t.headers {
		fmt.Fprintf(w, " %s |", h)
	}
	fmt.Fprintln(w)

	fmt.Fprint(w, "|")
	for _, wdt := range t.widths {
		fmt.Fprintf(w, " %s |", strings.Repeat("-", max(3, wdt)))
	}
	fmt.Fprintln(w)

	for _, r := range t.rows {
		fmt.Fprint(w, "|")
		for i, col := range r.cols {
			fmt.Fprintf(w, " %s |", PadANSI(col, t.widths[i]))
		}
		fmt.Fprintln(w)
	}
	_ = seps
}

// Render writes the table to w, auto-detecting TTY to choose format.
func (t *Table) Render(w io.Writer) {
	if IsTerminal(w) {
		t.RenderTTY(w)
	} else {
		t.RenderMarkdown(w)
	}
}

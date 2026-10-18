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

// RenderTTY writes the table to w using capabilities detected for w. Colour
// and Unicode are disabled for non-interactive destinations.
func (t *Table) RenderTTY(w io.Writer) {
	t.RenderTTYWithProfile(w, DetectProfile(w))
}

// RenderTTYWithProfile writes a fixed-width terminal table using profile. This
// is the profile-aware form of RenderTTY for deterministic callers and tests.
func (t *Table) RenderTTYWithProfile(w io.Writer, profile Profile) {
	profile = normalizeProfile(profile)
	display := func(value string) string {
		if !profile.Unicode {
			return SanitizeDisplayASCII(value)
		}
		return SanitizeDisplay(value)
	}
	paint := func(value, code string) string {
		if !profile.Interactive || profile.ColorDepth == ColorNone {
			return value
		}
		return Colorize(value, code)
	}

	// header
	for i, h := range t.headers {
		if i > 0 {
			fmt.Fprint(w, "  ")
		}
		h = display(h)
		fmt.Fprint(w, PadANSI(paint(h, Cyan+Bold), t.widths[i]))
	}
	fmt.Fprintln(w)

	// separator
	rule := "─"
	if !profile.Interactive || !profile.Unicode {
		rule = "-"
	}
	for i, wdt := range t.widths {
		if i > 0 {
			fmt.Fprint(w, "  ")
		}
		fmt.Fprint(w, paint(strings.Repeat(rule, wdt), Gray))
	}
	fmt.Fprintln(w)

	// data rows
	for _, r := range t.rows {
		for i, col := range r.cols {
			if i > 0 {
				fmt.Fprint(w, "  ")
			}
			v := display(col)
			if i < len(r.bg) && r.bg[i] != "" {
				v = paint(v, r.bg[i]+BgText)
			} else if i < len(r.fg) && r.fg[i] != "" {
				v = paint(v, r.fg[i])
			}
			fmt.Fprint(w, PadANSI(v, t.widths[i]))
		}
		fmt.Fprintln(w)
	}
}

// RenderMarkdown writes the table to w as a pipe-delimited markdown table.
func (t *Table) RenderMarkdown(w io.Writer) {
	display := SanitizeDisplay
	seps := func() string {
		return strings.Repeat("-", max(3, t.widths[0]))
	}
	fmt.Fprint(w, "|")
	for _, h := range t.headers {
		fmt.Fprintf(w, " %s |", display(h))
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
			fmt.Fprintf(w, " %s |", PadANSI(display(col), t.widths[i]))
		}
		fmt.Fprintln(w)
	}
	_ = seps
}

// RenderWithProfile writes the table using profile. Interactive destinations
// receive the fixed-width terminal form; all other destinations receive the
// machine-oriented markdown form without renderer-generated ANSI.
func (t *Table) RenderWithProfile(w io.Writer, profile Profile) {
	if normalizeProfile(profile).Interactive {
		t.RenderTTYWithProfile(w, profile)
		return
	}
	t.RenderMarkdown(w)
}

// Render writes the table to w, auto-detecting capabilities to choose format.
func (t *Table) Render(w io.Writer) {
	t.RenderWithProfile(w, DetectProfile(w))
}

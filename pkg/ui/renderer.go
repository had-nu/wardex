// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const maxContentWidth = 120

// Renderer owns the terminal presentation policy. Domain code should provide
// data to the renderer rather than printing ANSI sequences directly.
type Renderer struct {
	w       io.Writer
	profile Profile
	theme   Theme
}

// NewRenderer creates a renderer with an explicit capability profile. Passing
// an explicit profile makes rendering deterministic in tests and embedders.
func NewRenderer(w io.Writer, profile Profile) *Renderer {
	profile = normalizeProfile(profile)
	return &Renderer{
		w:       w,
		profile: profile,
		theme:   NewTheme(profile.ColorDepth),
	}
}

// NewDefaultRenderer detects capabilities from w and creates a renderer.
func NewDefaultRenderer(w io.Writer) *Renderer {
	return NewRenderer(w, DetectProfile(w))
}

// Profile returns the renderer's normalized capability profile.
func (r *Renderer) Profile() Profile {
	return r.profile
}

// ContentWidth returns the usable width for a single visual line.
func (r *Renderer) ContentWidth() int {
	width := max(min(r.profile.Width-1, maxContentWidth), MinWidth-1)
	return width
}

// Rule returns a horizontal rule using the best available line character.
func (r *Renderer) Rule() string {
	char := "─"
	if !r.profile.Unicode {
		char = "-"
	}
	return r.theme.Structure(strings.Repeat(char, r.ContentWidth()))
}

// KeyValue formats a stable two-column metadata line. labelWidth is measured
// in terminal cells using the same simple convention as VisibleLen; the UI
// currently uses single-cell labels and glyphs.
func (r *Renderer) KeyValue(label, value string, labelWidth int) string {
	if SensitiveLabel(label) {
		value = Redact(value)
	}
	if labelWidth < VisibleLen(label) {
		labelWidth = VisibleLen(label)
	}
	if maxLabel := r.ContentWidth() - 3; labelWidth > maxLabel {
		labelWidth = maxLabel
		label = truncate(label, labelWidth)
	}
	padded := PadANSI(label, labelWidth)
	plain := padded + "  " + value
	if r.ContentWidth() < VisibleLen(plain) {
		value = truncate(value, r.ContentWidth()-VisibleLen(padded)-2)
	}
	return r.theme.Muted(padded) + "  " + r.theme.Text(value)
}

// SectionHeader formats a left title and an optional right-aligned status.
func (r *Renderer) SectionHeader(title, status string) string {
	if status == "" {
		return r.theme.Heading(truncate(title, r.ContentWidth()))
	}

	right := truncate(status, max(1, r.ContentWidth()/3))
	left := truncate(title, max(1, r.ContentWidth()-VisibleLen(right)-1))
	gap := r.ContentWidth() - VisibleLen(left) - VisibleLen(right)
	if gap < 1 {
		return r.theme.Heading(left) + "  " + r.theme.Status(right, StatusNeutral)
	}
	return r.theme.Heading(left) + strings.Repeat(" ", gap) + r.theme.Status(right, StatusNeutral)
}

// Header writes the compact Wardex product header used at the beginning of an
// interactive session. It intentionally avoids a large ASCII logo so the
// layout remains useful in narrow terminals and fast-changing output.
func (r *Renderer) Header(version string) {
	marker := "◆"
	if !r.profile.Unicode {
		marker = "[*]"
	}
	title := marker + " WARDEX  RISK-BASED RELEASE GATE"
	right := truncate("v"+strings.TrimSpace(version), max(1, r.ContentWidth()/3))
	maxTitle := max(1, r.ContentWidth()-VisibleLen(right)-1)
	if VisibleLen(title) > maxTitle {
		title = marker + " WARDEX"
	}
	title = truncate(title, maxTitle)
	gap := r.ContentWidth() - VisibleLen(title) - VisibleLen(right)

	fmt.Fprintln(r.w)
	if gap >= 1 {
		fmt.Fprint(r.w, r.theme.Brand(title))
		fmt.Fprint(r.w, strings.Repeat(" ", gap))
	} else {
		fmt.Fprint(r.w, r.theme.Brand(title))
		fmt.Fprint(r.w, " ")
	}
	fmt.Fprintln(r.w, r.theme.Muted(right))
	fmt.Fprintln(r.w, r.Rule())
}

// PrintHeaderTo writes the interactive Wardex header to w. It returns false
// when w is not an interactive terminal, allowing callers to avoid polluting
// machine-readable output.
func PrintHeaderTo(w io.Writer, version string) bool {
	profile := DetectProfile(w)
	if !profile.Interactive {
		return false
	}
	NewRenderer(w, profile).Header(version)
	return true
}

func truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if VisibleLen(s) <= width {
		return s
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}

	var b strings.Builder
	used := 0
	for _, r := range s {
		runeWidth := runeCellWidth(r)
		if used+runeWidth > width-3 {
			break
		}
		b.WriteRune(r)
		used += runeWidth
	}
	b.WriteString("...")
	return b.String()
}

// truncateANSI truncates visible text while retaining escape sequences that
// occurred before the cut. It is used for already-coloured card content.
func truncateANSI(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if VisibleLen(s) <= width {
		return s
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}

	var b strings.Builder
	visible := 0
	styled := false
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			end := i + 1
			for end < len(s) && s[end] != 'm' {
				end++
			}
			if end < len(s) {
				end++
			}
			sequence := s[i:end]
			b.WriteString(sequence)
			if strings.HasSuffix(sequence, "m") {
				styled = true
			}
			i = end
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		runeWidth := runeCellWidth(r)
		if visible+runeWidth > width-3 {
			break
		}
		b.WriteRune(r)
		visible += runeWidth
		i += size
	}
	b.WriteString("...")
	if styled {
		b.WriteString(Reset)
	}
	return b.String()
}

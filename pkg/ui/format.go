// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"io"
	"strings"
	"unicode/utf8"
)

// ANSI text colour codes.
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

// ANSI background colour codes for badges / inline highlights.
const (
	BgRed    = "\033[41m"
	BgGreen  = "\033[42m"
	BgYellow = "\033[43m"
)

// BgText is bright-white foreground used on dark badge backgrounds.
const BgText = "\033[97m"

// Colorize wraps s in the ANSI code seq and appends Reset.
func Colorize(s string, code string) string {
	if code == "" || s == "" {
		return s
	}
	return code + s + Reset
}

// Redact removes a potentially sensitive value from human-facing output.
func Redact(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "[REDACTED]"
}

// SensitiveLabel reports whether a field should be redacted by default.
func SensitiveLabel(label string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(label))
	normalized = strings.NewReplacer(" ", "_", "-", "_", "\t", "_").Replace(normalized)
	for _, marker := range []string{"PAYLOAD", "SECRET", "TOKEN", "PASSWORD", "API_KEY", "CREDENTIAL"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

// VisibleLen returns the approximate terminal cell width of s, ignoring ANSI
// escape sequences. It covers the East Asian ranges commonly encountered in
// paths and evidence labels; the UI otherwise uses single-cell glyphs.
func VisibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		i += sz
		n += runeCellWidth(r)
	}
	return n
}

func runeCellWidth(r rune) int {
	if r == 0 || r < 32 || (r >= 0x7f && r < 0xa0) {
		return 0
	}
	if (r >= 0x1100 && r <= 0x115f) ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) ||
		(r >= 0x20000 && r <= 0x3fffd) {
		return 2
	}
	return 1
}

// PadANSI pads s with trailing spaces to width w, accounting for invisible ANSI codes.
func PadANSI(s string, w int) string {
	v := VisibleLen(s)
	if v >= w {
		return s
	}
	return s + strings.Repeat(" ", w-v)
}

// IsTerminal returns true when w is an interactive terminal. Character
// devices such as /dev/null are deliberately not treated as terminals.
func IsTerminal(w io.Writer) bool {
	return DetectProfile(w).Interactive
}

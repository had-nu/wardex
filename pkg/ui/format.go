// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"io"
	"strings"
	"unicode"
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

// SanitizeDisplay makes an untrusted value safe for human-facing terminal
// output. ANSI control sequences are removed, and C0/C1 controls, Unicode
// format controls and invalid UTF-8 are replaced without changing printable
// text. Structured encoders should serialize the original value instead.
func SanitizeDisplay(value string) string {
	if value == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteByte('?')
			i++
			continue
		}

		if r == '\x1b' {
			i = skipANSISequence(value, i)
			continue
		}
		if r >= 0x80 && r <= 0x9f {
			next := skipC1ANSISequence(value, i, size, r)
			if next != i {
				i = next
				continue
			}
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			b.WriteByte(' ')
			i += size
			continue
		}

		b.WriteRune(r)
		i += size
	}
	return b.String()
}

func skipANSISequence(value string, start int) int {
	if start+1 >= len(value) {
		return len(value)
	}

	switch value[start+1] {
	case '[':
		return skipCSI(value, start+2)
	case ']':
		return skipStringControl(value, start+2, true)
	case 'P', 'X', '^', '_':
		return skipStringControl(value, start+2, false)
	default:
		end := start + 1
		for end < len(value) && value[end] >= 0x20 && value[end] <= 0x2f {
			end++
		}
		if end < len(value) && value[end] >= 0x30 && value[end] <= 0x7e {
			end++
		}
		return end
	}
}

func skipC1ANSISequence(value string, start, size int, control rune) int {
	next := start + size
	switch control {
	case 0x9b: // CSI
		return skipCSI(value, next)
	case 0x9d: // OSC
		return skipStringControl(value, next, true)
	case 0x90, 0x98, 0x9e, 0x9f: // DCS, SOS, PM and APC
		return skipStringControl(value, next, false)
	default:
		return start
	}
}

func skipCSI(value string, start int) int {
	for i := start; i < len(value); i++ {
		if value[i] >= 0x40 && value[i] <= 0x7e {
			return i + 1
		}
	}
	return len(value)
}

func skipStringControl(value string, start int, allowBell bool) int {
	for i := start; i < len(value); i++ {
		if allowBell && value[i] == '\a' {
			return i + 1
		}
		if value[i] == '\x1b' && i+1 < len(value) && value[i+1] == '\\' {
			return i + 2
		}
		if value[i] == '\x9c' {
			return i + 1
		}
	}
	return len(value)
}

// SanitizeDisplayASCII additionally maps common presentation glyphs to
// ASCII and replaces other non-ASCII characters for TERM=dumb/C locales.
func SanitizeDisplayASCII(value string) string {
	value = SanitizeDisplay(value)
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r <= unicode.MaxASCII {
			b.WriteRune(r)
			continue
		}
		switch r {
		case '—', '–', '−':
			b.WriteByte('-')
		case '→':
			b.WriteString("->")
		case '·':
			b.WriteByte('|')
		case '✓':
			b.WriteByte('+')
		case '✗':
			b.WriteByte('x')
		case '▶':
			b.WriteByte('>')
		case '◆':
			b.WriteByte('*')
		case '█':
			b.WriteByte('#')
		case '…':
			b.WriteString("...")
		case '“', '”':
			b.WriteByte('"')
		case '‘', '’':
			b.WriteByte('\'')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
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

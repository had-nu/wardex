// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"io"
	"os"
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

// VisibleLen returns the visible length of s, ignoring ANSI escape sequences.
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
		_, sz := utf8.DecodeRuneInString(s[i:])
		i += sz
		n++
	}
	return n
}

// PadANSI pads s with trailing spaces to width w, accounting for invisible ANSI codes.
func PadANSI(s string, w int) string {
	v := VisibleLen(s)
	if v >= w {
		return s
	}
	return s + strings.Repeat(" ", w-v)
}

// IsTerminal returns true when w is an os.File connected to a character device (tty).
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

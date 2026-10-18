// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeDisplayASCII(t *testing.T) {
	got := SanitizeDisplayASCII("status — ✓ → ·")
	if got != "status - + -> |" {
		t.Fatalf("unexpected ASCII sanitization: %q", got)
	}
}

func TestSanitizeDisplay(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "sgr", input: "before\x1b[31mred\x1b[0mafter", want: "beforeredafter"},
		{name: "osc-bel", input: "before\x1b]0;window-title\aafter", want: "beforeafter"},
		{name: "osc-string-terminator", input: "before\x1b]0;window-title\x1b\\after", want: "beforeafter"},
		{name: "c1-csi", input: "before\u009b31mred\u009b0mafter", want: "beforeredafter"},
		{name: "c0-controls", input: "one\ntwo\rthree\tfour\x00five", want: "one two three four five"},
		{name: "bidi-format", input: "left\u202Eright", want: "left right"},
		{name: "invalid-utf8", input: "bad\xffvalue", want: "bad?value"},
		{name: "unterminated-ansi", input: "safe\x1b[31", want: "safe"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeDisplay(tc.input)
			if got != tc.want {
				t.Fatalf("SanitizeDisplay(%q) = %q, want %q", tc.input, got, tc.want)
			}
			if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\u009b') {
				t.Fatalf("sanitized value retained an escape introducer: %q", got)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("sanitized value is not valid UTF-8: %q", got)
			}
		})
	}
}

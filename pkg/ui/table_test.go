// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTableRenderWithProfileMatrix(t *testing.T) {
	tests := []struct {
		name        string
		profile     Profile
		wantANSI    bool
		wantUnicode bool
		wantTable   bool
	}{
		{
			name:        "ansi-unicode",
			profile:     Profile{Interactive: true, ColorDepth: ColorANSI, Unicode: true, Width: 80},
			wantANSI:    true,
			wantUnicode: true,
			wantTable:   true,
		},
		{
			name:      "ansi-ascii",
			profile:   Profile{Interactive: true, ColorDepth: ColorANSI, Unicode: false, Width: 80},
			wantANSI:  true,
			wantTable: true,
		},
		{
			name:        "no-color",
			profile:     Profile{Interactive: true, ColorDepth: ColorNone, Unicode: true, Width: 80},
			wantUnicode: true,
			wantTable:   true,
		},
		{
			name:      "term-dumb",
			profile:   Profile{Interactive: true, ColorDepth: ColorNone, Unicode: false, Width: 80},
			wantTable: true,
		},
		{
			name: "ci-noninteractive",
			// A colour-capable value cannot bypass the non-interactive guard.
			profile: Profile{Interactive: false, ColorDepth: ColorANSI, Unicode: true, Width: 80},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table := NewTable([]string{"NAME", "STATE"}, []int{12, 10})
			table.AddRowStyled([]string{"artifact", "PASS"}, []string{Red, Green}, nil)

			var out bytes.Buffer
			table.RenderWithProfile(&out, tc.profile)
			got := out.String()

			if hasANSI := strings.Contains(got, "\x1b["); hasANSI != tc.wantANSI {
				t.Fatalf("ANSI presence = %v, want %v: %q", hasANSI, tc.wantANSI, got)
			}
			if hasUnicodeRule := strings.Contains(got, "─"); hasUnicodeRule != tc.wantUnicode {
				t.Fatalf("Unicode rule presence = %v, want %v: %q", hasUnicodeRule, tc.wantUnicode, got)
			}
			if hasMarkdown := strings.HasPrefix(got, "|"); hasMarkdown == tc.wantTable {
				t.Fatalf("markdown presence = %v, want terminal table = %v: %q", hasMarkdown, tc.wantTable, got)
			}
		})
	}
}

func TestTableRenderOnNonInteractiveDestinationIsUndecorated(t *testing.T) {
	table := NewTable([]string{"NAME"}, []int{16})
	table.AddRowColor([]string{"artifact"}, []string{Cyan})

	var out bytes.Buffer
	table.Render(&out)
	got := out.String()

	if !strings.HasPrefix(got, "|") {
		t.Fatalf("pipe destination did not receive machine table: %q", got)
	}
	if strings.Contains(got, "\x1b[") || strings.Contains(got, "─") {
		t.Fatalf("pipe destination received terminal decoration: %q", got)
	}
}

func TestTableRenderUsesDetectedProfileForEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		wantANSI    bool
		wantUnicode bool
		wantTable   bool
	}{
		{name: "default", wantANSI: true, wantUnicode: true, wantTable: true},
		{name: "no-color", env: map[string]string{"NO_COLOR": "1"}, wantUnicode: true, wantTable: true},
		{name: "term-dumb", env: map[string]string{"TERM": "dumb"}, wantTable: true},
		{name: "ci", env: map[string]string{"CIRCLECI": "true"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(key string) string { return tc.env[key] }
			profile := applyEnvironment(Profile{
				Interactive: true,
				Unicode:     true,
				Width:       80,
			}, lookup)

			table := NewTable([]string{"NAME"}, []int{16})
			table.AddRowColor([]string{"artifact"}, []string{Cyan})
			var out bytes.Buffer
			table.RenderWithProfile(&out, profile)
			got := out.String()

			if hasANSI := strings.Contains(got, "\x1b["); hasANSI != tc.wantANSI {
				t.Fatalf("ANSI presence = %v, want %v: %q", hasANSI, tc.wantANSI, got)
			}
			if hasUnicodeRule := strings.Contains(got, "─"); hasUnicodeRule != tc.wantUnicode {
				t.Fatalf("Unicode rule presence = %v, want %v: %q", hasUnicodeRule, tc.wantUnicode, got)
			}
			if hasMarkdown := strings.HasPrefix(got, "|"); hasMarkdown == tc.wantTable {
				t.Fatalf("markdown presence = %v, want terminal table = %v: %q", hasMarkdown, tc.wantTable, got)
			}
		})
	}
}

func TestTableTerminalRenderingSanitizesValues(t *testing.T) {
	table := NewTable([]string{"NA\x1b[31mME"}, []int{24})
	table.AddRow("\x1b]0;window-title\aartifact\nnext\x00")

	var out bytes.Buffer
	table.RenderTTYWithProfile(&out, Profile{
		Interactive: true,
		ColorDepth:  ColorNone,
		Unicode:     true,
		Width:       80,
	})
	got := out.String()

	if strings.ContainsAny(got, "\x1b\x00\r\t") {
		t.Fatalf("terminal table contains unsafe display controls: %q", got)
	}
	if !strings.Contains(got, "NAME") || !strings.Contains(got, "artifact next") {
		t.Fatalf("terminal table lost printable sanitized text: %q", got)
	}
	if strings.Contains(got, "window-title") {
		t.Fatalf("terminal table retained an OSC payload: %q", got)
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestRendererHeaderTrueColor(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out, Profile{
		Interactive: true,
		ColorDepth:  ColorTrueColor,
		Unicode:     true,
		Width:       80,
	})

	r.Header("2.6.0")
	got := out.String()

	if !strings.Contains(got, "WARDEX") {
		t.Fatalf("header missing product name: %q", got)
	}
	if !strings.Contains(got, "v2.6.0") {
		t.Fatalf("header missing version: %q", got)
	}
	if !strings.Contains(got, "\033[38;2;") {
		t.Fatalf("true-color header has no true-color sequence: %q", got)
	}
	if strings.Contains(got, "m;1") {
		t.Fatalf("bold escape sequence is malformed: %q", got)
	}
	if !strings.Contains(got, "─") {
		t.Fatalf("unicode profile did not render a unicode rule: %q", got)
	}
}

func TestRendererHeaderPlainASCII(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out, Profile{
		Interactive: true,
		ColorDepth:  ColorNone,
		Unicode:     false,
		Width:       40,
	})

	r.Header("2.6.0")
	got := out.String()

	if strings.Contains(got, "\033[") {
		t.Fatalf("plain profile contains ANSI escapes: %q", got)
	}
	if strings.Contains(got, "◆") || strings.Contains(got, "─") {
		t.Fatalf("ASCII profile contains unicode glyphs: %q", got)
	}
	if !strings.Contains(got, "[*] WARDEX") {
		t.Fatalf("ASCII marker missing: %q", got)
	}
}

func TestRendererKeyValueTruncatesLongValue(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out, Profile{
		ColorDepth: ColorNone,
		Unicode:    true,
		Width:      32,
	})

	got := r.KeyValue("Description", strings.Repeat("x", 100), 12)
	if VisibleLen(got) > r.ContentWidth() {
		t.Fatalf("key/value line exceeds content width: %d > %d", VisibleLen(got), r.ContentWidth())
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("long value was not truncated: %q", got)
	}
}

func TestVisibleLenAccountsForWideRunes(t *testing.T) {
	if got := VisibleLen("界a"); got != 3 {
		t.Fatalf("expected wide rune width 2 plus ASCII width 1, got %d", got)
	}
	if got := VisibleLen(truncate("界界界", 4)); got > 4 {
		t.Fatalf("wide-rune truncation exceeded width: %d", got)
	}
}

func TestRendererKeyValueRedactsSensitiveFields(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out, Profile{ColorDepth: ColorNone, Unicode: true, Width: 80})
	got := r.KeyValue("API_KEY", "super-secret-value", 14)
	if strings.Contains(got, "super-secret-value") {
		t.Fatalf("sensitive value was not redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("redaction marker missing: %q", got)
	}
}

func TestPrintHeaderToSkipsNonInteractiveWriter(t *testing.T) {
	var out bytes.Buffer
	if PrintHeaderTo(&out, "2.6.0") {
		t.Fatal("expected non-interactive writer to skip header")
	}
	if out.Len() != 0 {
		t.Fatalf("non-interactive writer received output: %q", out.String())
	}
}

func TestThemeColorNoneIsPlain(t *testing.T) {
	theme := NewTheme(ColorNone)
	for name, got := range map[string]string{
		"brand":   theme.Brand("brand"),
		"heading": theme.Heading("heading"),
		"status":  theme.Status("RUNNING", StatusRunning),
	} {
		if got != strings.TrimSpace(got) || strings.Contains(got, "\033[") {
			t.Fatalf("%s theme emitted styling in plain mode: %q", name, got)
		}
	}
}

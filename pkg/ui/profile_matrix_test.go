// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestRendererTerminalProfileMatrix(t *testing.T) {
	cases := []struct {
		name        string
		profile     Profile
		wantANSI    bool
		wantUnicode bool
	}{
		{
			name: "ascii-plain-narrow",
			profile: Profile{
				Interactive: true, ColorDepth: ColorNone, Unicode: false, Width: 32,
			},
		},
		{
			name: "ascii-ansi",
			profile: Profile{
				Interactive: true, ColorDepth: ColorANSI, Unicode: false, Width: 80,
			},
			wantANSI: true,
		},
		{
			name: "unicode-plain",
			profile: Profile{
				Interactive: true, ColorDepth: ColorNone, Unicode: true, Width: 80,
			},
			wantUnicode: true,
		},
		{
			name: "unicode-truecolor",
			profile: Profile{
				Interactive: true, ColorDepth: ColorTrueColor, Unicode: true, Width: 120,
			},
			wantANSI: true, wantUnicode: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			renderer := NewRenderer(&out, tc.profile)
			renderer.Dashboard(testDashboard())
			got := out.String()

			if strings.Contains(got, "\033[") != tc.wantANSI {
				t.Fatalf("ANSI presence = %v, want %v", strings.Contains(got, "\033["), tc.wantANSI)
			}
			if strings.Contains(got, "─") != tc.wantUnicode {
				t.Fatalf("Unicode rule presence = %v, want %v", strings.Contains(got, "─"), tc.wantUnicode)
			}
			for line := range strings.SplitSeq(got, "\n") {
				if VisibleLen(line) > renderer.ContentWidth() {
					t.Fatalf("line exceeds profile width (%d > %d): %q", VisibleLen(line), renderer.ContentWidth(), line)
				}
			}
		})
	}
}

func TestProfileEnvironmentMatrix(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		wantUnicode bool
		wantCI      bool
	}{
		{name: "utf8-default", env: map[string]string{}, wantUnicode: true},
		{name: "utf8-locale", env: map[string]string{"LANG": "pt_BR.UTF-8"}, wantUnicode: true},
		{name: "ascii-locale", env: map[string]string{"LANG": "C"}, wantUnicode: false},
		{name: "dumb-terminal", env: map[string]string{"TERM": "dumb", "LANG": "C.UTF-8"}, wantUnicode: false},
		{name: "github-actions", env: map[string]string{"GITHUB_ACTIONS": "true"}, wantUnicode: true, wantCI: true},
		{name: "ci-disabled", env: map[string]string{"CI": "false", "LANG": "C.UTF-8"}, wantUnicode: true, wantCI: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(key string) string { return tc.env[key] }
			if got := unicodeSupported(lookup); got != tc.wantUnicode {
				t.Fatalf("unicodeSupported = %v, want %v", got, tc.wantUnicode)
			}
			if got := isCI(lookup); got != tc.wantCI {
				t.Fatalf("isCI = %v, want %v", got, tc.wantCI)
			}
		})
	}
}

func TestProfileEnvironmentCapabilities(t *testing.T) {
	base := Profile{Interactive: true, Unicode: true, Width: 80}
	tests := []struct {
		name        string
		env         map[string]string
		wantColor   ColorDepth
		wantUnicode bool
		wantWidth   int
	}{
		{name: "default-ansi", env: map[string]string{}, wantColor: ColorANSI, wantUnicode: true, wantWidth: 80},
		{name: "no-color", env: map[string]string{"NO_COLOR": "1"}, wantColor: ColorNone, wantUnicode: true, wantWidth: 80},
		{name: "dumb", env: map[string]string{"TERM": "dumb"}, wantColor: ColorNone, wantUnicode: false, wantWidth: 80},
		{name: "truecolor", env: map[string]string{"COLORTERM": "truecolor"}, wantColor: ColorTrueColor, wantUnicode: true, wantWidth: 80},
		{name: "ci", env: map[string]string{"CI": "true"}, wantColor: ColorNone, wantUnicode: false, wantWidth: DefaultWidth},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(key string) string { return tc.env[key] }
			input := base
			input.Unicode = unicodeSupported(lookup)
			got := applyEnvironment(input, lookup)
			if got.ColorDepth != tc.wantColor || got.Unicode != tc.wantUnicode || got.Width != tc.wantWidth {
				t.Fatalf("profile = %+v, want color=%v unicode=%v width=%d", got, tc.wantColor, tc.wantUnicode, tc.wantWidth)
			}
		})
	}
}

func TestPipeDestinationsRemainUndecorated(t *testing.T) {
	var out bytes.Buffer
	if PrintHeaderTo(&out, "2.6.0") {
		t.Fatal("pipe destination unexpectedly accepted interactive header")
	}
	if out.Len() != 0 {
		t.Fatalf("pipe destination received header bytes: %q", out.String())
	}

	if RenderResults(&out, testDashboard()) {
		t.Fatal("pipe destination unexpectedly accepted interactive results")
	}
	if out.Len() != 0 {
		t.Fatalf("pipe destination received result bytes: %q", out.String())
	}
}

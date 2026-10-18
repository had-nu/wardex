// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestTextLoggerProfileMatrix(t *testing.T) {
	tests := []struct {
		name     string
		profile  Profile
		wantANSI bool
	}{
		{
			name:     "interactive-ansi",
			profile:  Profile{Interactive: true, ColorDepth: ColorANSI, Width: 80},
			wantANSI: true,
		},
		{
			name:    "no-color",
			profile: Profile{Interactive: true, ColorDepth: ColorNone, Width: 80},
		},
		{
			name:    "term-dumb",
			profile: Profile{Interactive: true, ColorDepth: ColorNone, Width: 80},
		},
		{
			name:    "noninteractive",
			profile: Profile{Interactive: false, ColorDepth: ColorANSI, Width: 80},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			NewLoggerToWithProfile(&out, slog.LevelInfo, tc.profile).Info("ready", "component", "ui")

			got := out.String()
			if hasANSI := strings.Contains(got, "\x1b["); hasANSI != tc.wantANSI {
				t.Fatalf("ANSI presence = %v, want %v: %q", hasANSI, tc.wantANSI, got)
			}
			want := "[INFO] ready component=ui\n"
			if tc.wantANSI {
				want = Cyan + "[INFO]" + Reset + " ready component=ui\n"
			}
			if !strings.Contains(got, want) {
				t.Fatalf("unexpected text log: %q", got)
			}
		})
	}
}

func TestNewLoggerToDetectsNonInteractiveDestination(t *testing.T) {
	var out bytes.Buffer
	NewLoggerTo(&out, slog.LevelInfo).Warn("warning")

	if got := out.String(); strings.Contains(got, "\x1b[") || got != "[WARN] warning\n" {
		t.Fatalf("non-interactive text logger was decorated: %q", got)
	}
}

func TestTextLoggerSanitizesDisplayValues(t *testing.T) {
	var out bytes.Buffer
	logger := NewLoggerToWithProfile(&out, slog.LevelInfo, Profile{
		Interactive: true,
		ColorDepth:  ColorNone,
		Width:       80,
	})
	logger.Info(
		"prefix \x1b[31mred\nnext",
		"\x1b[2Jkey",
		"\x1b]0;window-title\avalue\x00",
	)

	got := out.String()
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\x00") || strings.Count(got, "\n") != 1 {
		t.Fatalf("text logger emitted unsafe display controls: %q", got)
	}
	if !strings.Contains(got, "prefix red next") || !strings.Contains(got, "key=value") {
		t.Fatalf("text logger lost sanitized printable text: %q", got)
	}
	if strings.Contains(got, "window-title") {
		t.Fatalf("text logger retained an OSC payload: %q", got)
	}
}

func TestJSONLoggerPreservesMachineValues(t *testing.T) {
	const (
		message   = "machine\nmessage\x1b[31m"
		attrKey   = "key\x1b[2J"
		attrValue = "value\x00\x1b[0m"
	)

	var out bytes.Buffer
	handler := newJSONHandler(&out, slog.LevelInfo)
	record := slog.NewRecord(time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC), slog.LevelInfo, message, 0)
	record.AddAttrs(slog.String(attrKey, attrValue))
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatalf("handle JSON record: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	if decoded["message"] != message {
		t.Fatalf("machine message changed: got %q, want %q", decoded["message"], message)
	}
	if decoded[attrKey] != attrValue {
		t.Fatalf("machine attr changed: got %q, want %q", decoded[attrKey], attrValue)
	}
}

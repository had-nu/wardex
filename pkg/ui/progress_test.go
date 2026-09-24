// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalProgressIsDisabledForBuffer(t *testing.T) {
	var out bytes.Buffer
	progress := NewTerminalProgress(&out)
	if progress.Enabled() {
		t.Fatal("buffer progress reporter should be disabled")
	}
	progress.Begin(SessionView{Title: "SESSION", Status: "RUNNING"})
	progress.Report(PhaseEvent{Number: 1, Name: "Config", Status: "DONE"})
	if out.Len() != 0 {
		t.Fatalf("disabled progress reporter wrote output: %q", out.String())
	}
}

func TestTerminalProgressExplicitRenderer(t *testing.T) {
	var out bytes.Buffer
	profile := Profile{Interactive: true, ColorDepth: ColorNone, Unicode: true, Width: 80}
	progress := &TerminalProgress{w: &out, renderer: NewRenderer(&out, profile), enabled: true}

	progress.Begin(SessionView{
		Title:  "EVALUATION SESSION",
		Status: "RUNNING",
		Fields: []Field{{Label: "INPUT", Value: "controls.yml"}},
	})
	progress.Report(PhaseEvent{Number: 1, Name: "Loading configuration", Status: "RUNNING"})
	progress.Report(PhaseEvent{Number: 1, Name: "Loading configuration", Status: "DONE", Detail: "loaded"})

	got := out.String()
	for _, want := range []string{"EVALUATION SESSION", "RUNNING", "Loading configuration", "DONE", "loaded"} {
		if !strings.Contains(got, want) {
			t.Fatalf("progress output missing %q: %q", want, got)
		}
	}
}

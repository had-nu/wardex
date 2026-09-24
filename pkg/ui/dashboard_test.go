// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"strings"
	"testing"
)

func testDashboard() Dashboard {
	return Dashboard{
		Session: SessionView{
			Title:  "EVALUATION SESSION",
			Status: "COMPLETE",
			Fields: []Field{
				{Label: "Input", Value: "controls.yml"},
				{Label: "Framework", Value: "iso27001"},
			},
		},
		Phases: []PhaseView{
			{Number: 1, Name: "Loading configuration", Status: "DONE", Detail: "configuration loaded"},
			{Number: 2, Name: "Computing gaps", Status: "COMPLETE", Detail: "3 gaps"},
		},
		Findings: []FindingView{{
			Severity:   "HIGH",
			Title:      "Missing evidence for control",
			Confidence: "0.90",
			Fields:     []Field{{Label: "Control", Value: "A.5.15"}},
		}},
		Summary: SummaryView{
			Decision: "BLOCK",
			Fields: []Field{
				{Label: "Coverage", Value: "78%"},
				{Label: "Gaps", Value: "3"},
			},
		},
	}
}

func TestRendererDashboardPlainLayout(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out, Profile{
		Interactive: true,
		ColorDepth:  ColorNone,
		Unicode:     false,
		Width:       80,
	})

	r.Dashboard(testDashboard())
	got := out.String()

	for _, want := range []string{
		"EVALUATION SESSION",
		"COMPLETE",
		"Loading configuration",
		"COMPLIANCE GAP",
		"HIGH",
		"EXECUTIVE SUMMARY",
		"BLOCK",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("dashboard missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\033[") {
		t.Fatalf("plain dashboard contains ANSI escapes:\n%q", got)
	}
	if strings.Contains(got, "│") || strings.Contains(got, "┌") {
		t.Fatalf("ASCII dashboard contains unicode box drawing:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if VisibleLen(line) > 80 {
			t.Fatalf("line exceeds test width (%d): %q", VisibleLen(line), line)
		}
	}
}

func TestRendererDashboardUsesSemanticColors(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out, Profile{
		Interactive: true,
		ColorDepth:  ColorTrueColor,
		Unicode:     true,
		Width:       100,
	})

	r.Dashboard(testDashboard())
	got := out.String()

	if !strings.Contains(got, "\033[38;2;240;79;109m") {
		t.Fatalf("danger status did not use danger colour:\n%q", got)
	}
	if !strings.Contains(got, "\033[38;2;42;181;220m") {
		t.Fatalf("structural border did not use structure colour:\n%q", got)
	}
}

func TestRenderDashboardSkipsNonInteractiveWriter(t *testing.T) {
	var out bytes.Buffer
	if RenderDashboard(&out, testDashboard()) {
		t.Fatal("expected non-interactive dashboard to be skipped")
	}
	if out.Len() != 0 {
		t.Fatalf("non-interactive dashboard wrote output: %q", out.String())
	}
}

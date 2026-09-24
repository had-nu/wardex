// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "update UI golden files")

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden || os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden directory: %v", err)
		}
		if err := os.WriteFile(path, canonicalGolden(got), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", name, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update-golden to create it)", name, err)
	}
	if bytes.Equal(canonicalGolden(want), canonicalGolden(got)) {
		return
	}

	firstDifference := min(len(got), len(want))
	for firstDifference < len(want) && firstDifference < len(got) && want[firstDifference] == got[firstDifference] {
		firstDifference++
	}
	t.Fatalf("golden %s differs at byte %d\nwant: %q\n got: %q", name, firstDifference, excerpt(want, firstDifference), excerpt(got, firstDifference))
}

func canonicalGolden(value []byte) []byte {
	return append(bytes.TrimRight(value, "\n"), '\n')
}

func excerpt(value []byte, at int) string {
	const radius = 80
	start := max(at-radius, 0)
	end := min(at+radius, len(value))
	return string(value[start:end])
}

func goldenProfile(width int) Profile {
	return Profile{
		Interactive: true,
		ColorDepth:  ColorNone,
		Unicode:     false,
		Width:       width,
	}
}

func TestGoldenDashboardASCII(t *testing.T) {
	var out bytes.Buffer
	NewRenderer(&out, goldenProfile(80)).Dashboard(testDashboard())
	assertGolden(t, "dashboard-ascii.golden", out.Bytes())
}

func TestGoldenDashboardNarrowASCII(t *testing.T) {
	var out bytes.Buffer
	NewRenderer(&out, goldenProfile(40)).Dashboard(testDashboard())
	assertGolden(t, "dashboard-narrow-ascii.golden", out.Bytes())
}

func TestGoldenProgressASCII(t *testing.T) {
	var out bytes.Buffer
	profile := goldenProfile(64)
	progress := &TerminalProgress{
		w:        &out,
		renderer: NewRenderer(&out, profile),
		enabled:  true,
	}

	progress.Begin(SessionView{
		Title:  "RELEASE GATE SESSION",
		Status: "RUNNING",
		Fields: []Field{
			{Label: "COMMAND", Value: "EVALUATE"},
			{Label: "CONFIG", Value: "wardex-config.yaml"},
		},
	})
	progress.Report(PhaseEvent{Number: 1, Name: "Loading configuration", Status: "RUNNING", Detail: "config.yaml"})
	progress.Report(PhaseEvent{Number: 1, Name: "Loading configuration", Status: "DONE", Detail: "configuration loaded"})
	progress.Report(PhaseEvent{Number: 2, Name: "Computing gaps", Status: "DONE", Detail: "3 findings"})

	assertGolden(t, "progress-ascii.golden", out.Bytes())
}

func TestGoldenHeaderASCII(t *testing.T) {
	var out bytes.Buffer
	NewRenderer(&out, goldenProfile(48)).Header("2.6.0")
	assertGolden(t, "header-ascii.golden", out.Bytes())
}

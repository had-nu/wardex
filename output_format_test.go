// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"strings"
	"testing"

	"github.com/had-nu/wardex/v3/pkg/report"
	"github.com/had-nu/wardex/v3/pkg/ui"
)

// TestMachineOutputValueMatchesUIPolicy guards against the banner classifier
// drifting from the format policy that suppresses progress and dashboards.
// These were two separate lists; a format added to one and not the other
// produced a banner on a machine-format run.
func TestMachineOutputValueMatchesUIPolicy(t *testing.T) {
	for _, format := range []string{
		"json", "JSONL", "csv", "cbor", "yaml", "yml", "html", "HTML", " JSON ", "Csv",
	} {
		if !machineOutputValue(format) {
			t.Errorf("machineOutputValue(%q) = false, want true", format)
		}
		if !ui.IsMachineFormat(format) {
			t.Errorf("ui.IsMachineFormat(%q) = false, want true", format)
		}
	}

	for _, format := range []string{"markdown", "table", "", "text", "htm"} {
		if machineOutputValue(format) {
			t.Errorf("machineOutputValue(%q) = true, want false", format)
		}
	}
}

// TestEveryReportFormatIsMachineOrHuman pins the classification for each format
// the CLI advertises, so a new format cannot be added without deciding whether
// it gets human decoration.
func TestEveryReportFormatIsMachineOrHuman(t *testing.T) {
	wantMachine := map[string]bool{
		"markdown": false,
		"json":     true,
		"csv":      true,
		"html":     true,
	}
	for _, format := range report.SupportedFormats() {
		expected, ok := wantMachine[format]
		if !ok {
			t.Errorf("format %q is advertised by the CLI but not classified in this test; "+
				"decide whether it is a machine format and add it", format)
			continue
		}
		if got := ui.IsMachineFormat(format); got != expected {
			t.Errorf("ui.IsMachineFormat(%q) = %v, want %v", format, got, expected)
		}
	}
}

// TestFormatListMatchesSupportedFormats keeps flag help honest.
func TestFormatListMatchesSupportedFormats(t *testing.T) {
	list := report.FormatList()
	for _, format := range report.SupportedFormats() {
		if !strings.Contains(list, format) {
			t.Errorf("flag help %q does not advertise supported format %q", list, format)
		}
	}
	if !report.IsSupportedFormat("html") {
		t.Error("html is implemented and tested in pkg/report but not offered by the CLI")
	}
}

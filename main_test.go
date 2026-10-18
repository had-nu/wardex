// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/orchestrator"
	"github.com/spf13/cobra"
)

func TestMachineCommandClassification(t *testing.T) {
	for _, path := range []string{"wardex completion", "wardex help", "wardex audit export", "wardex audit verify-link", "wardex config hash", "wardex provenance attest"} {
		if !machineCommandPath(path) {
			t.Errorf("expected machine path %q", path)
		}
	}
	for _, format := range []string{"json", "JSONL", "csv", "cbor", "yaml"} {
		if !machineOutputValue(format) {
			t.Errorf("expected machine format %q", format)
		}
	}
	if machineCommandPath("wardex keygen") || machineOutputValue("table") || machineOutputValue("markdown") {
		t.Fatal("human path/format was classified as machine-oriented")
	}
}

func TestBuildEvaluationErrorDashboard(t *testing.T) {
	dashboard := buildEvaluationErrorDashboard(orchestrator.EvaluationOptions{}, "controls could not be loaded")
	if dashboard.Session.Status != "FAILED" || dashboard.Summary.Decision != "ERROR" || len(dashboard.Findings) != 1 {
		t.Fatalf("unexpected error dashboard: %+v", dashboard)
	}
}

func TestRunWardexUsesConfiguredWriters(t *testing.T) {
	controls, err := filepath.Abs("test/testdata/documented-controls.yaml")
	if err != nil {
		t.Fatal(err)
	}

	oldConfigPath, oldOutputFormat, oldOutFile := configPath, outputFormat, outFile
	oldFramework, oldMinConfidence, oldNoSnapshot := frameworkName, minConfidence, noSnapshot
	oldRoadmapLimit, oldEPSSEnrich, oldExitFunc := roadmapLimit, epssEnrich, exitFunc
	t.Cleanup(func() {
		configPath, outputFormat, outFile = oldConfigPath, oldOutputFormat, oldOutFile
		frameworkName, minConfidence, noSnapshot = oldFramework, oldMinConfidence, oldNoSnapshot
		roadmapLimit, epssEnrich, exitFunc = oldRoadmapLimit, oldEPSSEnrich, oldExitFunc
	})

	configPath = filepath.Join(t.TempDir(), "missing-config.yaml")
	outputFormat = "markdown"
	outFile = "stdout"
	frameworkName = "iso27001"
	minConfidence = "low"
	noSnapshot = true
	roadmapLimit = 0
	epssEnrich = ""

	var exitCode int
	exitFunc = func(code int) { exitCode = code }

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{Use: "wardex"}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	runWardex(cmd, []string{controls})

	if exitCode != 0 {
		t.Fatalf("unexpected exit code %d; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# ISO/IEC 27001:2022 — Compliance & Release Gate Report") {
		t.Fatalf("expected report on configured stdout, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("non-TTY stdout contains ANSI: %q", stdout.String())
	}
}

// TestReportTitleNamesTheFrameworkThatRan is the regression guard for the hardcoded
// "ISO 27001:2022" title: every run produced an artefact claiming ISO 27001
// regardless of --framework, because GapReport carried no framework.
func TestReportTitleNamesTheFrameworkThatRan(t *testing.T) {
	controls, err := filepath.Abs("test/testdata/documented-controls.yaml")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		framework string
		want      string
	}{
		{"iso27001", "ISO/IEC 27001:2022"},
		{"nis2", "NIS2"},
		{"dora", "DORA"},
		{"nist_csf", "NIST CSF"},
		{"eu_ai_act", "EU AI Act"},
	} {
		t.Run(tc.framework, func(t *testing.T) {
			oldConfigPath, oldOutputFormat, oldOutFile := configPath, outputFormat, outFile
			oldFramework, oldNoSnapshot := frameworkName, noSnapshot
			oldExitFunc := exitFunc
			t.Cleanup(func() {
				configPath, outputFormat, outFile = oldConfigPath, oldOutputFormat, oldOutFile
				frameworkName, noSnapshot = oldFramework, oldNoSnapshot
				exitFunc = oldExitFunc
			})

			configPath = filepath.Join(t.TempDir(), "missing-config.yaml")
			outputFormat = "markdown"
			outFile = "stdout"
			frameworkName = tc.framework
			noSnapshot = true

			var exitCode int
			exitFunc = func(code int) { exitCode = code }

			var stdout, stderr bytes.Buffer
			cmd := &cobra.Command{Use: "wardex"}
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			runWardex(cmd, []string{controls})

			if exitCode != 0 {
				t.Fatalf("unexpected exit code %d; stderr=%q", exitCode, stderr.String())
			}
			report := stdout.String()
			if !strings.Contains(report, tc.want) {
				t.Fatalf("report for --framework %s does not name %q; got %q", tc.framework, tc.want, firstLine(report))
			}
			if tc.framework != "iso27001" && strings.Contains(report, "ISO/IEC 27001") {
				t.Fatalf("report for --framework %s claims ISO/IEC 27001; got %q", tc.framework, firstLine(report))
			}
		})
	}
}

func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}

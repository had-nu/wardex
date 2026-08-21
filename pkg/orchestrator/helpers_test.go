// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"bytes"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

func TestGateLabel(t *testing.T) {
	cases := []struct {
		decision model.Decision
		label    string
	}{
		{model.DecisionBlock, "BLOCK"},
		{model.DecisionWarn, "WARN"},
		{model.DecisionAllow, "ALLOW"},
		{model.Decision("bogus"), "ALLOW"},
	}
	for _, c := range cases {
		_, label := gateLabel(c.decision)
		if label != c.label {
			t.Errorf("gateLabel(%s) = %q, want %q", c.decision, label, c.label)
		}
	}
}

func TestRiskColor(t *testing.T) {
	if c := riskColor(0.9, 0.6, 0.3); c != ui.Red {
		t.Errorf("expected red for risk >= appetite")
	}
	if c := riskColor(0.5, 0.6, 0.3); c != ui.Yellow {
		t.Errorf("expected yellow for warnAbove threshold")
	}
	if c := riskColor(0.1, 0.6, 0.3); c != ui.Green {
		t.Errorf("expected green for low risk")
	}
	if c := riskColor(0.5, 0.6, 0); c != ui.Green {
		t.Errorf("expected green when warnAbove disabled")
	}
}

func TestDryRunGateBlockAndCompliance(t *testing.T) {
	var buf bytes.Buffer
	opts := GateOptions{Stderr: &buf, FailAbove: 0.2}

	// BLOCK report prints the GateBlocked outcome.
	report := model.GateReport{OverallDecision: model.DecisionBlock}
	if code := dryRunGate(opts, report, "gate.log"); code != exitcodes.OK {
		t.Fatalf("dry-run must always return OK, got %d", code)
	}
	if buf.Len() == 0 {
		t.Fatalf("expected dry-run output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("GateBlocked")) {
		t.Fatalf("expected GateBlocked mention in dry-run output")
	}

	// ALLOW report with a risk above fail-above prints the ComplianceFail outcome.
	buf.Reset()
	report = model.GateReport{
		OverallDecision: model.DecisionAllow,
		Decisions: []model.ReleaseDecision{{
			Vulnerability: model.Vulnerability{CVEID: "CVE-2024-0001"},
			ReleaseRisk:   0.9,
		}},
	}
	if code := dryRunGate(opts, report, "gate.log"); code != exitcodes.OK {
		t.Fatalf("dry-run must always return OK, got %d", code)
	}
	if !bytes.Contains(buf.Bytes(), []byte("ComplianceFail")) {
		t.Fatalf("expected ComplianceFail mention in dry-run output")
	}
}

func TestHintMissingEPSS(t *testing.T) {
	var buf bytes.Buffer
	opts := GateOptions{Stderr: &buf, GateFile: "evidence.yaml"}

	withMissing := []model.Vulnerability{{CVEID: "CVE-1", EPSSScore: 0.0}}
	hintMissingEPSS(opts, withMissing)
	if !bytes.Contains(buf.Bytes(), []byte("lacked EPSS")) {
		t.Fatalf("expected hint when EPSS scores are missing")
	}

	buf.Reset()
	allScored := []model.Vulnerability{{CVEID: "CVE-1", EPSSScore: 0.5}}
	hintMissingEPSS(opts, allScored)
	if buf.Len() != 0 {
		t.Fatalf("expected no hint when all EPSS scores are present")
	}
}

func TestCollectCLIOverrides(t *testing.T) {
	opts := GateOptions{
		GateMode:    "aggregate",
		FailAbove:   0.5,
		EPSSEnrich:  "enrich.yaml",
		ProfileName: "ops",
		Strict:      true,
		DryRun:      true,
	}
	over := collectCLIOverrides(opts)
	for _, k := range []string{"gate-mode", "fail-above", "epss-enrichment", "profile", "strict", "dry-run"} {
		if _, ok := over[k]; !ok {
			t.Errorf("expected override %q to be collected", k)
		}
	}

	empty := collectCLIOverrides(GateOptions{})
	if len(empty) != 0 {
		t.Fatalf("expected no overrides for default flags, got %d", len(empty))
	}
}

func TestFormatDuration(t *testing.T) {
	if d := formatDuration(-time.Second); d != "passed" {
		t.Errorf("expected passed, got %q", d)
	}
	if d := formatDuration(5*time.Hour + 30*time.Minute); d != "5h 30m" {
		t.Errorf("expected 5h 30m, got %q", d)
	}
	if d := formatDuration(26*time.Hour + 5*time.Minute); d != "1d 2h" {
		t.Errorf("expected 1d 2h, got %q", d)
	}
}

func TestIsCI(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	if isCI() {
		t.Fatalf("isCI must be false without CI variables")
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	if !isCI() {
		t.Fatalf("isCI must be true with GITHUB_ACTIONS set")
	}
}

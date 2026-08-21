// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
)

const testControlsYAML = `controls:
  - id: "CTRL-IDAM-01"
    name: "Identity and Access Management Policy"
    description: "MFA mandatory for production systems."
    maturity: 4
    layer: implemented
    domains: ["organizational", "people"]
    evidences:
      - type: "policy"
        ref: "confluence:sec-001"
      - type: "log"
        ref: "okta:mfa_enrolment_rate"
    context_weight: 1.8
    weight_justification: "Critical gatekeeper for all internal access."
`

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func baseEvalOptions(dir string) EvaluationOptions {
	return EvaluationOptions{
		ConfigPath:    "wardex-config.yaml",
		Framework:     "iso27001",
		Inputs:        []string{"controls.yaml"},
		MinConfidence: "low",
		SnapshotFile:  ".wardex_snapshot.json",
		OutputFormat:  "markdown",
		OutFile:       "report.md",
		RoadmapLimit:  0,
		Logger:        discardLogger(),
		Stderr:        io.Discard,
	}
}

func TestNewEvaluationPipelineDefaults(t *testing.T) {
	p := NewEvaluationPipeline(EvaluationOptions{})
	if p.Logger == nil {
		t.Fatalf("expected a default logger")
	}
	if p.Stderr == nil {
		t.Fatalf("expected a default stderr writer")
	}
}

func TestRunBasicFlow(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "wardex-config.yaml", "{}\n")
	writeFixture(t, dir, "controls.yaml", testControlsYAML)

	opts := baseEvalOptions(dir)
	res, err := NewEvaluationPipeline(opts).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != exitcodes.OK {
		t.Fatalf("expected exit OK, got %d", res.ExitCode)
	}
	if res.ExitReason != ExitOK {
		t.Fatalf("expected ExitOK, got %q", res.ExitReason)
	}
	if len(res.Report.Findings) == 0 {
		t.Fatalf("expected findings for iso27001 catalog")
	}
	if res.Report.Summary.TotalControls != len(res.Report.Findings) {
		t.Fatalf("summary total controls mismatch: %d != %d", res.Report.Summary.TotalControls, len(res.Report.Findings))
	}
	if len(res.Report.Summary.DomainSummaries) == 0 {
		t.Fatalf("expected domain summaries")
	}
	if res.Report.Summary.GlobalCoverage < 0 || res.Report.Summary.GlobalCoverage > 100 {
		t.Fatalf("invalid global coverage: %f", res.Report.Summary.GlobalCoverage)
	}
	for i := 1; i < len(res.Report.Roadmap); i++ {
		if res.Report.Roadmap[i-1].FinalScore < res.Report.Roadmap[i].FinalScore {
			t.Fatalf("roadmap not sorted descending at %d", i)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "report.md")); err != nil {
		t.Fatalf("markdown report not generated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".wardex_snapshot.json")); err != nil {
		t.Fatalf("snapshot not written: %v", err)
	}
}

func TestRunSnapshotDelta(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "wardex-config.yaml", "{}\n")
	writeFixture(t, dir, "controls.yaml", testControlsYAML)

	opts := baseEvalOptions(dir)
	p := NewEvaluationPipeline(opts)

	if _, err := p.Run(context.Background(), opts); err != nil {
		t.Fatalf("first run failed: %v", err)
	}

	// Second run loads the previous snapshot and produces a delta.
	res, err := p.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if res.Report.Delta == nil {
		t.Fatalf("expected a snapshot delta on the second run")
	}
}

func TestRunGateBlocked(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "wardex-config.yaml", `release_gate:
  enabled: true
  mode: "any"
  risk_appetite: 0.6
  warn_above: 0.3
  asset_context:
    criticality: 0.9
    internet_facing: true
    requires_auth: true
    environment: "production"
`)
	writeFixture(t, dir, "controls.yaml", testControlsYAML)
	writeFixture(t, dir, "evidence.yaml", `vulnerabilities:
  - cve_id: "CVE-2024-BLOCK1"
    cvss_base: 10.0
    epss_score: 1.0
    component: "log4j:2.17.0"
    reachable: true
`)

	opts := baseEvalOptions(dir)
	opts.GateFile = "evidence.yaml"
	res, err := NewEvaluationPipeline(opts).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != exitcodes.GateBlocked {
		t.Fatalf("expected GateBlocked (%d), got %d", exitcodes.GateBlocked, res.ExitCode)
	}
	if res.ExitReason != ExitGateBlocked {
		t.Fatalf("expected ExitGateBlocked, got %q", res.ExitReason)
	}
	if res.GateReport == nil {
		t.Fatalf("expected a gate report")
	}
	if res.GateReport.OverallDecision != model.DecisionBlock {
		t.Fatalf("expected gate decision BLOCK, got %s", res.GateReport.OverallDecision)
	}
	if res.Report.Gate == nil {
		t.Fatalf("expected gate attached to the gap report")
	}
}

func TestRunComplianceFail(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "wardex-config.yaml", "{}\n")
	writeFixture(t, dir, "controls.yaml", testControlsYAML)

	opts := baseEvalOptions(dir)
	opts.FailAbove = 0.1
	res, err := NewEvaluationPipeline(opts).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != exitcodes.ComplianceFail {
		t.Fatalf("expected ComplianceFail (%d), got %d", exitcodes.ComplianceFail, res.ExitCode)
	}
	if res.ExitReason != ExitCompliance {
		t.Fatalf("expected ExitCompliance, got %q", res.ExitReason)
	}
}

func TestRunInvalidFramework(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "wardex-config.yaml", "{}\n")
	writeFixture(t, dir, "controls.yaml", testControlsYAML)

	opts := baseEvalOptions(dir)
	opts.Framework = "not-a-framework"
	if _, err := NewEvaluationPipeline(opts).Run(context.Background(), opts); err == nil {
		t.Fatalf("expected error for unsupported framework")
	}
}

func TestRunMissingConfigIsLenient(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "controls.yaml", testControlsYAML)

	opts := baseEvalOptions(dir)
	opts.ConfigPath = "missing-config.yaml"
	res, err := NewEvaluationPipeline(opts).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != exitcodes.OK {
		t.Fatalf("expected OK with missing config, got %d", res.ExitCode)
	}
}

func TestRunMinConfidenceHigh(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "wardex-config.yaml", "{}\n")
	writeFixture(t, dir, "controls.yaml", testControlsYAML)

	opts := baseEvalOptions(dir)
	opts.MinConfidence = "high"
	res, err := NewEvaluationPipeline(opts).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != exitcodes.OK {
		t.Fatalf("expected OK, got %d", res.ExitCode)
	}
}

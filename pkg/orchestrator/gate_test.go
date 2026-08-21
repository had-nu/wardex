// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/trust"
)

func writeGateFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func baseGateOptions(dir string) GateOptions {
	return GateOptions{
		ConfigPath:   "config.yaml",
		GateMode:     "any",
		GateFile:     "evidence.yaml",
		Controls:     []string{"controls.yaml"},
		Logger:       discardLogger(),
		Stderr:       io.Discard,
		Stdout:       io.Discard,
		OutputFormat: "markdown",
		OutFile:      "stdout",
	}
}

const gateControlsYAML = `controls:
  - id: "CTRL-01"
    name: "Access Control Policy"
    maturity: 3
    layer: implemented
    domains: ["organizational"]
`

func allowEvidence() string {
	return `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-LOW"
    cvss_base: 5.0
    epss_score: 0.5
    component: "curl:8.6.0"
    reachable: true
`
}

func blockEvidence() string {
	return `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-HIGH"
    cvss_base: 10.0
    epss_score: 1.0
    component: "log4j:2.17.0"
    reachable: true
`
}

func setupGateEnv(t *testing.T) {
	t.Setenv("WARDEX_ACCEPT_SECRET", "wardex-test-secret-not-production")
}

func TestRunGateAllow(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.GateLogPath = "gate.log"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "gate.log")); err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
}

func TestRunGateBlock(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", `release_gate:
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
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", blockEvidence())

	code, err := RunGate(context.Background(), baseGateOptions(dir))
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.GateBlocked {
		t.Fatalf("expected GateBlocked (%d), got %d", exitcodes.GateBlocked, code)
	}
}

func TestRunGateMissingEPSSBlocks(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-UNSCORED"
    cvss_base: 9.0
    epss_score: 0.0
    component: "openssl:3.2.0"
    reachable: true
`)

	code, err := RunGate(context.Background(), baseGateOptions(dir))
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.ComplianceFail {
		t.Fatalf("expected ComplianceFail (%d), got %d", exitcodes.ComplianceFail, code)
	}
}

func TestRunGateStrictUnsealedConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.Strict = true
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.IntegrityFailure {
		t.Fatalf("expected IntegrityFailure (%d), got %d", exitcodes.IntegrityFailure, code)
	}
}

func TestRunGateDryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.DryRun = true
	opts.GateLogPath = "gate.log"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "gate.log")); err == nil {
		t.Fatalf("dry-run must not write the audit log")
	}
}

func TestRunGateCSVOutput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.OutputFormat = "csv"
	opts.OutFile = "out.csv"
	opts.GateLogPath = "/dev/null"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK, got %d", code)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.csv"))
	if err != nil {
		t.Fatalf("CSV output not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("empty CSV output")
	}
}

func TestRunGateLoadControlsError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.Controls = []string{"does-not-exist.yaml"}
	if _, err := RunGate(context.Background(), opts); err == nil {
		t.Fatalf("expected error for missing controls file")
	}
}

func TestRunGateActiveExploitation(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", `release_gate: {enabled: true, risk_appetite: 1.0}
cra:
  art14:
    product_name: "Wardex"
    product_version: "2.5.0"
    awareness_source: "now"
`)
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-EXPLOITED"
    cvss_base: 9.8
    epss_score: 0.95
    component: "fortios:7.4.0"
    reachable: true
    actively_exploited: true
`)

	opts := baseGateOptions(dir)
	opts.Art14OutDir = "art14"
	opts.GateLogPath = "/dev/null"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.ActivelyExploited {
		t.Fatalf("expected ActivelyExploited (%d), got %d", exitcodes.ActivelyExploited, code)
	}
	artefacts, err := filepath.Glob(filepath.Join(dir, "art14", "wardex-art14-*.json"))
	if err != nil || len(artefacts) == 0 {
		t.Fatalf("expected a written Article 14 artefact: %v", err)
	}
}

func TestRunGateActiveExploitationDryRun(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-EXPLOITED"
    cvss_base: 9.8
    epss_score: 0.95
    component: "fortios:7.4.0"
    reachable: true
    actively_exploited: true
`)

	opts := baseGateOptions(dir)
	opts.DryRun = true
	opts.Art14OutDir = "art14"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK on dry-run, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "art14")); err == nil {
		t.Fatalf("dry-run must not write Article 14 artefacts")
	}
}

func TestRunGateStateStore(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", `release_gate: {enabled: true, risk_appetite: 1.0}
state_store:
  enabled: true
  dir: ".wardex"
`)
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.GateLogPath = "/dev/null"

	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK, got %d", code)
	}
	entries, err := filepath.Glob(filepath.Join(dir, ".wardex", "*"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected state store records: %v", err)
	}

	// Second run with --trend shows the formatted trend analysis.
	opts.ShowTrend = true
	code, err = RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate (trend) failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK on trend run, got %d", code)
	}
}

func TestRunGateJSONOutput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.OutputFormat = "json"
	opts.OutFile = "out.json"
	opts.GateLogPath = "/dev/null"
	opts.GateMode = "aggregate"
	opts.FailAbove = 9.0
	opts.EPSSEnrich = "enrich.yaml"
	opts.ProfileName = "ops"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK, got %d", code)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.json"))
	if err != nil {
		t.Fatalf("JSON output not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("empty JSON output")
	}
}

func TestRunGateSealedConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)

	keyPath := filepath.Join(dir, "admin.wex")
	storePath := filepath.Join(dir, "wardex-trust.yaml")
	draftPath := filepath.Join(dir, "draft.yaml")
	wexPath := filepath.Join(dir, "wardex.wexstate")

	if _, err := trust.GenerateKeypair(keyPath, false); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := trust.InitStore(keyPath, "admin@test.com", "Admin", storePath, ""); err != nil {
		t.Fatalf("init store: %v", err)
	}
	writeGateFixture(t, dir, "draft.yaml", "release_gate:\n  enabled: true\n  risk_appetite: 1.0\n")
	if err := trust.SealConfig(context.Background(), keyPath, draftPath, wexPath, storePath); err != nil {
		t.Fatalf("seal config: %v", err)
	}
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.ConfigPath = "wardex.wexstate"
	opts.GateLogPath = "/dev/null"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate with sealed config failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("expected OK, got %d", code)
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
)

func TestResolveClassProfileDefaults(t *testing.T) {
	cfg := &config.Config{}
	pr, err := resolveClassProfile(config.ClassPR, cfg)
	if err != nil {
		t.Fatalf("pr: %v", err)
	}
	if pr.integrity != severityBlock || pr.policy != severityBlock {
		t.Errorf("pr must block integrity/policy, got %v/%v", pr.integrity, pr.policy)
	}
	if pr.freshness != severityAdvisory {
		t.Errorf("pr freshness must be advisory, got %v", pr.freshness)
	}
	if pr.activeExploit != severityOff {
		t.Errorf("pr active_exploit must be off, got %v", pr.activeExploit)
	}

	deploy, err := resolveClassProfile(config.ClassDeploy, cfg)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if deploy.integrity != severityBlock || deploy.policy != severityBlock ||
		deploy.freshness != severityBlock || deploy.activeExploit != severityBlock {
		t.Errorf("deploy must block everything, got %+v", deploy)
	}

	nightly, err := resolveClassProfile(config.ClassNightly, cfg)
	if err != nil {
		t.Fatalf("nightly: %v", err)
	}
	if nightly.integrity != severityOff || nightly.policy != severityOff ||
		nightly.freshness != severityAdvisory || nightly.activeExploit != severityOff {
		t.Errorf("nightly profile wrong: %+v", nightly)
	}

	// Empty class resolves to deploy (caller default), not an error.
	empty, err := resolveClassProfile("", cfg)
	if err != nil {
		t.Fatalf("empty class: %v", err)
	}
	if empty.name != config.ClassDeploy {
		t.Errorf("empty class must map to deploy, got %s", empty.name)
	}
}

func TestResolveClassProfileOverrides(t *testing.T) {
	cfg := &config.Config{
		ReleaseGate: config.ReleaseGate{
			Classes: map[string]map[string]string{
				"pr": {"freshness": "block", "active_exploit": "advisory"},
			},
		},
	}
	pr, err := resolveClassProfile(config.ClassPR, cfg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pr.freshness != severityBlock {
		t.Errorf("override freshness->block failed, got %v", pr.freshness)
	}
	if pr.activeExploit != severityAdvisory {
		t.Errorf("override active_exploit->advisory failed, got %v", pr.activeExploit)
	}
}

func TestResolveClassProfileRejectsBadInput(t *testing.T) {
	cases := []struct {
		name  string
		class string
		cfg   *config.Config
	}{
		{"unknown class", "canary", &config.Config{}},
		{"bad exam", "pr", &config.Config{ReleaseGate: config.ReleaseGate{Classes: map[string]map[string]string{"pr": {"traffic": "block"}}}}},
		{"bad severity", "pr", &config.Config{ReleaseGate: config.ReleaseGate{Classes: map[string]map[string]string{"pr": {"freshness": "always"}}}}},
	}
	for _, c := range cases {
		if _, err := resolveClassProfile(c.class, c.cfg); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func classBaseOpts(dir, class string) GateOptions {
	opts := baseGateOptions(dir)
	opts.GateClass = class
	return opts
}

func TestRunGatePRClassFreshnessAdvisory(t *testing.T) {
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

	code, err := RunGate(context.Background(), classBaseOpts(dir, config.ClassPR))
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.FreshnessAdvisory {
		t.Fatalf("expected FreshnessAdvisory (%d), got %d", exitcodes.FreshnessAdvisory, code)
	}
}

func TestRunGateNightlyFreshnessAdvisory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-UNSCORED"
    cvss_base: 5.0
    epss_score: 0.0
    component: "openssl:3.2.0"
    reachable: true
`)

	code, err := RunGate(context.Background(), classBaseOpts(dir, config.ClassNightly))
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.FreshnessAdvisory {
		t.Fatalf("expected FreshnessAdvisory (%d), got %d", exitcodes.FreshnessAdvisory, code)
	}
}

func TestRunGatePRClassOverrideFreshnessBlock(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", `release_gate:
  enabled: true
  risk_appetite: 1.0
  classes:
    pr:
      freshness: block
`)
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-UNSCORED"
    cvss_base: 9.0
    epss_score: 0.0
    component: "openssl:3.2.0"
    reachable: true
`)

	code, err := RunGate(context.Background(), classBaseOpts(dir, config.ClassPR))
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.ComplianceFail {
		t.Fatalf("overridden freshness must hard-block (%d), got %d", exitcodes.ComplianceFail, code)
	}
}

func TestRunGateNightlyPolicyBlockReports(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 0.6}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", blockEvidence())

	opts := classBaseOpts(dir, config.ClassNightly)
	opts.GateLogPath = "/dev/null"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("nightly must report policy block (exit 0), got %d", code)
	}
}

func TestRunGatePRActiveExploitationNoHardStop(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-EXPLOITED"
    cvss_base: 5.0
    epss_score: 0.95
    component: "fortios:7.4.0"
    reachable: true
    actively_exploited: true
`)

	opts := classBaseOpts(dir, config.ClassPR)
	opts.Art14OutDir = "art14"
	opts.GateLogPath = "/dev/null"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.OK {
		t.Fatalf("pr must not hard-stop on active exploitation, got %d", code)
	}
	if artefacts, _ := filepath.Glob(filepath.Join(dir, "art14", "wardex-art14-*.json")); len(artefacts) != 0 {
		t.Fatalf("pr must not mandate an Article 14 artefact, found %v", artefacts)
	}
}

func TestRunGateUnknownClass(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", allowEvidence())

	opts := baseGateOptions(dir)
	opts.GateClass = "canary"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.GenericError {
		t.Fatalf("unknown class must be GenericError (%d), got %d", exitcodes.GenericError, code)
	}
}

func TestRunGateDeployActiveExploitationStillHardStop(t *testing.T) {
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

	opts := classBaseOpts(dir, config.ClassDeploy)
	opts.Art14OutDir = "art14"
	opts.GateLogPath = "/dev/null"
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.ActivelyExploited {
		t.Fatalf("deploy must keep the hard stop (%d), got %d", exitcodes.ActivelyExploited, code)
	}
}

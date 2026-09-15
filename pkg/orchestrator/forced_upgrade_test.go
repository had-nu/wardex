// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
)

const unscoredEvidence = `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-UNSCORED"
    cvss_base: 5.0
    epss_score: 0.0
    component: "openssl:3.2.0"
    reachable: true
`

const scoredEvidence = `converted_by: "test-converter"
vulnerabilities:
  - cve_id: "CVE-2024-SCORED"
    cvss_base: 5.0
    epss_score: 0.75
    component: "openssl:3.2.0"
    reachable: true
`

func forcedUpgradeOpts(dir, class, counterPath string) GateOptions {
	opts := classBaseOpts(dir, class)
	opts.GateLogPath = filepath.Join(dir, "gate.log")
	opts.Art14OutDir = "art14"
	opts.ForcedUpgradeState = counterPath
	return opts
}

// readAuditEvents parses every chained audit entry in the gate log.
func readAuditEvents(t *testing.T, path string) []model.AuditEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entries []model.AuditEntry
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		if sc.Text() == "" {
			continue
		}
		var e model.AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("parse audit entry: %v", err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestRunGateForcedUpgradeWithoutConfigUnchanged(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", unscoredEvidence)

	// Class pr + missing EPSS without forced_upgrade → advisory exit 6, not 10.
	code, err := RunGate(context.Background(), classBaseOpts(dir, config.ClassPR))
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.FreshnessAdvisory {
		t.Fatalf("expected FreshnessAdvisory (%d), got %d", exitcodes.FreshnessAdvisory, code)
	}
}

func TestRunGateForcedUpgradeBlocksUnattestable(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", `release_gate:
  enabled: true
  risk_appetite: 1.0
  forced_upgrade:
    enabled: true
`)
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", unscoredEvidence)

	counterPath := filepath.Join(dir, "fugate", "forced_upgrade.json")
	opts := forcedUpgradeOpts(dir, config.ClassPR, counterPath)

	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.GateBlocked {
		t.Fatalf("armed forced_upgrade must block unattestable release (%d), got %d", exitcodes.GateBlocked, code)
	}

	events := readAuditEvents(t, opts.GateLogPath)
	got := make([]string, 0, len(events))
	for _, e := range events {
		got = append(got, e.Event)
	}
	if len(got) != 1 || got[0] != eventForcedUpgradeArmed {
		t.Fatalf("expected a single forced_upgrade.armed entry, got %v", got)
	}
}

func TestRunGateForcedUpgradeTripwireDisarmsThenRearms(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", `release_gate:
  enabled: true
  risk_appetite: 1.0
  forced_upgrade:
    enabled: true
    tripwire_failures: 2
`)
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", unscoredEvidence)

	counterPath := filepath.Join(dir, "fugate", "forced_upgrade.json")
	opts := forcedUpgradeOpts(dir, config.ClassPR, counterPath)

	// Failure 1: armed, so the unattestable release blocks (exit 10).
	if code, err := RunGate(context.Background(), opts); err != nil || code != exitcodes.GateBlocked {
		t.Fatalf("run 1: code=%d err=%v, want GateBlocked", code, err)
	}

	// Failure 2: tripwire (N=2) disarms → fall back to class exam → pr advisory 6.
	if code, err := RunGate(context.Background(), opts); err != nil || code != exitcodes.FreshnessAdvisory {
		t.Fatalf("run 2: code=%d err=%v, want FreshnessAdvisory", code, err)
	}

	// Fresh evidence returns → re-arm and ALLOW (policy allow, scored EPSS).
	writeGateFixture(t, dir, "evidence.yaml", scoredEvidence)
	if code, err := RunGate(context.Background(), opts); err != nil || code != exitcodes.OK {
		t.Fatalf("run 3: code=%d err=%v, want OK", code, err)
	}

	events := readAuditEvents(t, opts.GateLogPath)
	var sequence []string
	for _, e := range events {
		sequence = append(sequence, e.Event)
	}
	want := []string{
		eventForcedUpgradeArmed,    // activation (run 1)
		eventForcedUpgradeDisarmed, // tripwire at N=2 (run 2)
		"gate.evaluated",           // run 2 falls back to policy eval after disarm
		eventForcedUpgradeArmed,    // re-arm after fresh evidence (run 3)
		"gate.evaluated",           // run 3 completes normally
	}
	if len(sequence) != len(want) {
		t.Fatalf("audit sequence = %v, want %v", sequence, want)
	}
	for i := range want {
		if sequence[i] != want[i] {
			t.Fatalf("audit sequence = %v, want %v", sequence, want)
		}
	}

	// Counter reflects the re-armed state.
	data, err := os.ReadFile(counterPath)
	if err != nil {
		t.Fatalf("tripwire state missing: %v", err)
	}
	var st struct {
		Consecutive int  `json:"consecutive"`
		Armed       bool `json:"armed"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("parse tripwire state: %v", err)
	}
	if !st.Armed || st.Consecutive != 0 {
		t.Errorf("tripwire state after re-arm = %+v, want armed with 0 consecutive", st)
	}
}

func TestRunGateForcedUpgradeDefaultTripwire(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", `release_gate:
  enabled: true
  risk_appetite: 1.0
  forced_upgrade:
    enabled: true
`)
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", unscoredEvidence)

	counterPath := filepath.Join(dir, "fugate", "forced_upgrade.json")
	opts := forcedUpgradeOpts(dir, config.ClassPR, counterPath)

	for i := 1; i <= config.DefaultForcedUpgradeTripwireFailures-1; i++ {
		code, err := RunGate(context.Background(), opts)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if code != exitcodes.GateBlocked {
			t.Fatalf("run %d: expected GateBlocked, got %d", i, code)
		}
	}
	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("run %d: %v", config.DefaultForcedUpgradeTripwireFailures, err)
	}
	if code != exitcodes.FreshnessAdvisory {
		t.Fatalf("default tripwire must disarm at %d, got code %d", config.DefaultForcedUpgradeTripwireFailures, code)
	}
}

func TestRunGateForcedUpgradeByFlagWithoutConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupGateEnv(t)
	writeGateFixture(t, dir, "config.yaml", "release_gate: {enabled: true, risk_appetite: 1.0}\n")
	writeGateFixture(t, dir, "controls.yaml", gateControlsYAML)
	writeGateFixture(t, dir, "evidence.yaml", unscoredEvidence)

	counterPath := filepath.Join(dir, "fugate", "forced_upgrade.json")
	opts := forcedUpgradeOpts(dir, config.ClassPR, counterPath)
	opts.ForcedUpgrade = true

	code, err := RunGate(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunGate failed: %v", err)
	}
	if code != exitcodes.GateBlocked {
		t.Fatalf("flag activation must block while armed, got %d", code)
	}
}

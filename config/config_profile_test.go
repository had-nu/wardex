// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package config

import (
	"os"
	"testing"
)

func TestConfigProfileOverrides(t *testing.T) {
	yamlData := `
release_gate:
  enabled: true
  risk_appetite: 2.0
  warn_above: 1.0

profiles:
  strict-team:
    risk_appetite: 0.5
    warn_above: 0.1
  relaxed-team:
    risk_appetite: 10.0
    warn_above: 5.0
`
	tmpFile := "test-rbac-config.yaml"
	err := os.WriteFile(tmpFile, []byte(yamlData), 0644)
	if err != nil {
		t.Fatalf("Failed to create temporary config file: %v", err)
	}
	defer os.Remove(tmpFile)

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Test baseline
	if cfg.ReleaseGate.RiskAppetite != 2.0 {
		t.Errorf("Expected baseline RiskAppetite 2.0, got %f", cfg.ReleaseGate.RiskAppetite)
	}
	if cfg.ReleaseGate.WarnAbove != 1.0 {
		t.Errorf("Expected baseline WarnAbove 1.0, got %f", cfg.ReleaseGate.WarnAbove)
	}

	// Test strict profile override simulation
	if p, ok := cfg.Profiles["strict-team"]; ok {
		// This simulates the logic that occurs in main.go
		cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
		cfg.ReleaseGate.WarnAbove = p.WarnAbove
	} else {
		t.Fatalf("strict-team profile not parsed from YAML")
	}

	if cfg.ReleaseGate.RiskAppetite != 0.5 {
		t.Errorf("Expected strict RiskAppetite 0.5, got %f", cfg.ReleaseGate.RiskAppetite)
	}
	if cfg.ReleaseGate.WarnAbove != 0.1 {
		t.Errorf("Expected strict WarnAbove 0.1, got %f", cfg.ReleaseGate.WarnAbove)
	}

	// Test relaxed profile override simulation
	if p, ok := cfg.Profiles["relaxed-team"]; ok {
		cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
		cfg.ReleaseGate.WarnAbove = p.WarnAbove
	} else {
		t.Fatalf("relaxed-team profile not parsed from YAML")
	}

	if cfg.ReleaseGate.RiskAppetite != 10.0 {
		t.Errorf("Expected relaxed RiskAppetite 10.0, got %f", cfg.ReleaseGate.RiskAppetite)
	}
	if cfg.ReleaseGate.WarnAbove != 5.0 {
		t.Errorf("Expected relaxed WarnAbove 5.0, got %f", cfg.ReleaseGate.WarnAbove)
	}
}

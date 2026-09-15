// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package config

import (
	"os"
	"testing"
)

func TestForcedUpgradeConfigDecode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := "config.yaml"
	content := `release_gate:
  enabled: true
  risk_appetite: 0.7
  forced_upgrade:
    enabled: true
    deadline: "2026-09-14"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fu := cfg.ReleaseGate.ForcedUpgrade
	if fu == nil {
		t.Fatal("forced_upgrade must decode into ReleaseGate")
	}
	if !fu.Enabled {
		t.Error("forced_upgrade.enabled must be true")
	}
	if fu.Deadline != "2026-09-14" {
		t.Errorf("deadline = %q", fu.Deadline)
	}
	if got := fu.Tripwire(); got != DefaultForcedUpgradeTripwireFailures {
		t.Errorf("default tripwire = %d, want %d", got, DefaultForcedUpgradeTripwireFailures)
	}
}

func TestForcedUpgradeTripwireOverride(t *testing.T) {
	fu := &ForcedUpgradeConfig{TripwireFailures: 3}
	if got := fu.Tripwire(); got != 3 {
		t.Errorf("tripwire = %d, want 3", got)
	}
	if got := (&ForcedUpgradeConfig{TripwireFailures: -2}).Tripwire(); got != DefaultForcedUpgradeTripwireFailures {
		t.Errorf("negative tripwire must default, got %d", got)
	}
	if got := (*ForcedUpgradeConfig)(nil).Tripwire(); got != DefaultForcedUpgradeTripwireFailures {
		t.Errorf("nil tripwire must default, got %d", got)
	}
}

func TestConfigWithoutForcedUpgradeUnchanged(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := "config.yaml"
	if err := os.WriteFile(path, []byte("release_gate: {enabled: true, risk_appetite: 1.0}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ReleaseGate.ForcedUpgrade != nil {
		t.Fatal("forced_upgrade must stay nil when absent from config")
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package enrich implements evidence enrichment (EPSS) and carries the
// forced_upgrade tripwire failure counter (L7).
//
// The tripwire records consecutive evidence-refresh failures in a small
// persistent state file. After N consecutive failures the gate auto-disarms
// and returns to policy evaluation, so an absent or permanently stale evidence
// source can never freeze the release pipeline forever (P11).
package enrich

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultTripwireFailures mirrors config.DefaultForcedUpgradeTripwireFailures
// so callers that only hold the counter can still honour the default.
const DefaultTripwireFailures = 5

// defaultTripwireFile is the state file relative to the state-store directory.
const defaultTripwireFile = "forced_upgrade.json"

// defaultStateDir matches statestore's fallback working directory.
const defaultStateDir = ".wardex"

// TripwireFilePath returns the default tripwire counter path under dir. An
// empty dir selects ".wardex" (the state-store default directory).
func TripwireFilePath(dir string) string {
	if dir == "" {
		dir = defaultStateDir
	}
	return filepath.Join(dir, defaultTripwireFile)
}

// TripwireState is the persistent forced_upgrade tripwire counter (L7).
type TripwireState struct {
	// Consecutive is the number of consecutive evidence-refresh failures.
	Consecutive int `json:"consecutive"`
	// Armed reports whether the forced_upgrade gate is currently armed.
	// false means the tripwire has disarmed and the gate has fallen back to
	// policy evaluation.
	Armed bool `json:"armed"`
}

// LoadTripwire reads the persisted tripwire state. A missing file is a
// zero-state (disarmed, consecutive=0) and not an error.
func LoadTripwire(path string) (*TripwireState, error) {
	// #nosec G304 -- state path comes from caller-provided options/config
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &TripwireState{}, nil
		}
		return nil, fmt.Errorf("enrich: read tripwire state: %w", err)
	}
	var s TripwireState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("enrich: parse tripwire state: %w", err)
	}
	return &s, nil
}

// Save persists the tripwire state atomically with 0600 permissions.
func (s *TripwireState) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("enrich: tripwire state dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("enrich: marshal tripwire state: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { // #nosec G304 -- state path from caller config
		return fmt.Errorf("enrich: write tripwire state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("enrich: replace tripwire state: %w", err)
	}
	return nil
}

// Step advances the tripwire for one forced_upgrade gate run. failed=true
// records an evidence-refresh failure; failed=false records a successful
// refresh. n is the disarm threshold (n<1 selects DefaultTripwireFailures).
//
// Returns whether the gate remains armed after the step:
//   - failure before reaching N → holds armed
//   - failure reaching N → disarms (Armed=false), pipeline falls back to policy
//   - success after a disarm → re-arms (fresh evidence restores the deadline)
//   - success while armed → resets the consecutive counter
func (s *TripwireState) Step(failed bool, n int) bool {
	if n < 1 {
		n = DefaultTripwireFailures
	}
	if failed {
		s.Consecutive++
		if s.Consecutive >= n {
			s.Armed = false
		}
		return s.Armed
	}
	s.Consecutive = 0
	s.Armed = true
	return true
}

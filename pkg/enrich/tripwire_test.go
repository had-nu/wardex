// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package enrich

import (
	"os"
	"path/filepath"

	"testing"
)

func TestTripwireStepIncrementsThenDisarms(t *testing.T) {
	s := &TripwireState{Armed: true}
	if !s.Step(true, 5) {
		t.Fatalf("failure 1 must hold armed")
	}
	if s.Consecutive != 1 {
		t.Errorf("consecutive = %d, want 1", s.Consecutive)
	}
	for i := 2; i <= 4; i++ {
		if !s.Step(true, 5) {
			t.Fatalf("failure %d must still be armed", i)
		}
	}
	if s.Step(true, 5) {
		t.Fatalf("5th consecutive failure must disarm")
	}
	if s.Armed {
		t.Errorf("state must be disarmed after N consecutive failures")
	}
	if s.Consecutive != 5 {
		t.Errorf("consecutive = %d, want 5", s.Consecutive)
	}
}

func TestTripwireStepResetsOnSuccess(t *testing.T) {
	s := &TripwireState{Armed: true}
	_ = s.Step(true, 3)
	_ = s.Step(true, 3)
	if !s.Step(false, 3) {
		t.Fatalf("success must hold armed")
	}
	if s.Consecutive != 0 {
		t.Errorf("consecutive must reset to 0, got %d", s.Consecutive)
	}
}

func TestTripwireReArmsAfterFreshEvidence(t *testing.T) {
	s := &TripwireState{Armed: true}
	_ = s.Step(true, 2) // consecutive 1, armed
	if s.Step(true, 2) {
		t.Fatalf("2nd failure must disarm")
	}
	if s.Armed {
		t.Fatal("expected disarmed")
	}
	// Fresh evidence returns → re-arm.
	if !s.Step(false, 2) {
		t.Fatalf("fresh evidence must re-arm the gate")
	}
	if !s.Armed || s.Consecutive != 0 {
		t.Errorf("re-armed state wrong: armed=%v consecutive=%d", s.Armed, s.Consecutive)
	}
}

func TestTripwireDefaultThreshold(t *testing.T) {
	s := &TripwireState{Armed: true}
	for i := range DefaultTripwireFailures - 1 {
		if !s.Step(true, 0) {
			t.Fatalf("failure %d must hold with default threshold", i+1)
		}
	}
	if s.Step(true, 0) {
		t.Fatalf("default threshold must disarm on the %d-th failure", DefaultTripwireFailures)
	}
}

func TestTripwireStatePersistence(t *testing.T) {
	dir := t.TempDir()
	path := TripwireFilePath(dir)
	if filepath.Base(path) != "forced_upgrade.json" {
		t.Fatalf("unexpected path: %s", path)
	}
	if got := TripwireFilePath(""); got != ".wardex/forced_upgrade.json" {
		t.Fatalf("default state-store path = %q, want .wardex/forced_upgrade.json", got)
	}

	// Missing file → zero state, not an error.
	state, err := LoadTripwire(path)
	if err != nil {
		t.Fatalf("LoadTripwire(missing) = %v", err)
	}
	if state.Armed || state.Consecutive != 0 {
		t.Errorf("zero state wrong: %+v", state)
	}

	state.Armed = true
	state.Consecutive = 3
	if err := state.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("tripwire state mode = %o, want 0600", perm)
	}

	loaded, err := LoadTripwire(path)
	if err != nil {
		t.Fatalf("LoadTripwire(saved) = %v", err)
	}
	if !loaded.Armed || loaded.Consecutive != 3 {
		t.Errorf("round-trip mismatch: %+v", loaded)
	}
}

func TestTripwirePrunesToFilepath(t *testing.T) {
	if got := filepath.Base(TripwireFilePath("")); got != "forced_upgrade.json" {
		t.Fatalf("default dir base = %q", got)
	}
	if got := filepath.Base(TripwireFilePath("custom-dir")); got != "forced_upgrade.json" {
		t.Fatalf("custom dir base = %q", got)
	}
}

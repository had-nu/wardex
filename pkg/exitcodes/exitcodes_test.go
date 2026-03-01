// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package exitcodes

import (
	"testing"
)

func TestNoReservedPOSIXCodes(t *testing.T) {
	// POSIX reserves exit code 2 for "misuse of shell builtins"
	// and 126-255 for signal/shell internal errors.
	allCodes := []struct {
		name string
		code int
	}{
		{"OK", OK},
		{"GenericError", GenericError},
		{"Tampered", Tampered},
		{"StoreInconsistent", StoreInconsistent},
		{"ExpiringSoon", ExpiringSoon},
		{"GateBlocked", GateBlocked},
		{"ComplianceFail", ComplianceFail},
	}

	reservedCodes := map[int]string{
		2:   "misuse of shell builtins",
		126: "command invoked cannot execute",
		127: "command not found",
	}

	for _, ec := range allCodes {
		if reason, reserved := reservedCodes[ec.code]; reserved {
			t.Errorf("exit code %s=%d conflicts with POSIX reserved code: %s", ec.name, ec.code, reason)
		}
		if ec.code >= 128 && ec.code <= 255 {
			t.Errorf("exit code %s=%d falls in signal range 128-255", ec.name, ec.code)
		}
	}
}

func TestNoCollisions(t *testing.T) {
	allCodes := map[int]string{
		OK:                "OK",
		GenericError:      "GenericError",
		Tampered:          "Tampered",
		StoreInconsistent: "StoreInconsistent",
		ExpiringSoon:      "ExpiringSoon",
		GateBlocked:       "GateBlocked",
		ComplianceFail:    "ComplianceFail",
	}

	// If any two constants share a value, the map would have fewer entries
	expectedCount := 7
	if len(allCodes) != expectedCount {
		t.Errorf("exit code collision detected: expected %d unique codes, got %d", expectedCount, len(allCodes))
	}
}

func TestGateBlockedNotTwo(t *testing.T) {
	// Regression: the original bug was os.Exit(2) for gate block.
	// Ensure GateBlocked is never 2.
	if GateBlocked == 2 {
		t.Error("GateBlocked must not be 2 (POSIX reserved for shell builtin misuse)")
	}
}

func TestExpectedValues(t *testing.T) {
	// Pin exact values to prevent accidental changes
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"OK", OK, 0},
		{"GenericError", GenericError, 1},
		{"Tampered", Tampered, 3},
		{"StoreInconsistent", StoreInconsistent, 4},
		{"ExpiringSoon", ExpiringSoon, 5},
		{"GateBlocked", GateBlocked, 10},
		{"ComplianceFail", ComplianceFail, 11},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

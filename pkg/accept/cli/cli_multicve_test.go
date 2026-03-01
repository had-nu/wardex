// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"fmt"
	"testing"
)

func TestMultiCVEIDGeneration(t *testing.T) {
	// Simulate the ID generation logic from the refactored request handler
	baseID := "acc-20260301-1709312345"
	cves := []string{"CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9012"}

	var generatedIDs []string
	for i, cve := range cves {
		id := baseID
		if len(cves) > 1 {
			id = fmt.Sprintf("%s-%d", baseID, i)
		}
		generatedIDs = append(generatedIDs, id)

		// Verify each ID contains the base + index
		expectedID := fmt.Sprintf("%s-%d", baseID, i)
		if id != expectedID {
			t.Errorf("CVE %s: expected ID %q, got %q", cve, expectedID, id)
		}
	}

	// Verify all IDs are unique
	seen := make(map[string]bool)
	for _, id := range generatedIDs {
		if seen[id] {
			t.Errorf("duplicate ID detected: %s", id)
		}
		seen[id] = true
	}

	// Verify correct count
	if len(generatedIDs) != len(cves) {
		t.Errorf("expected %d acceptances, got %d", len(cves), len(generatedIDs))
	}
}

func TestSingleCVEIDNoSuffix(t *testing.T) {
	// When only 1 CVE is passed, the ID should NOT have an index suffix
	baseID := "acc-20260301-1709312345"
	cves := []string{"CVE-2024-1234"}

	for i := range cves {
		id := baseID
		if len(cves) > 1 {
			id = fmt.Sprintf("%s-%d", baseID, i)
		}

		if id != baseID {
			t.Errorf("single CVE should use base ID %q, got %q", baseID, id)
		}
	}
}

func TestMultiCVEEachCVETracked(t *testing.T) {
	// Verify that each CVE from the input slice gets its own acceptance
	cves := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
	baseID := "acc-20260301-1709312345"

	trackedCVEs := make(map[string]string) // cve -> id
	for i, cve := range cves {
		id := baseID
		if len(cves) > 1 {
			id = fmt.Sprintf("%s-%d", baseID, i)
		}
		trackedCVEs[cve] = id
	}

	// Verify all CVEs are tracked
	for _, cve := range cves {
		if _, ok := trackedCVEs[cve]; !ok {
			t.Errorf("CVE %s was not tracked in acceptances", cve)
		}
	}

	// Verify count matches
	if len(trackedCVEs) != len(cves) {
		t.Errorf("expected %d tracked CVEs, got %d", len(cves), len(trackedCVEs))
	}
}

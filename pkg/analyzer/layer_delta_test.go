// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
)

func TestComputeLayerDelta(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "C1", Layer: model.LayerDocumented},
		{ID: "C2", Layer: model.LayerDocumented},
		{ID: "C3", Layer: model.LayerImplemented}, // Paper ∩ Code
		{ID: "C4", Layer: model.LayerImplemented}, // Shadow Security
	}
	// Correcting the overlap: C3 should be in both
	controls = append(controls, model.ExistingControl{ID: "C3", Layer: model.LayerDocumented})

	a := &Analyzer{
		Controls: controls,
	}

	delta := a.ComputeLayerDelta()

	if delta.DocumentedCount != 3 {
		t.Errorf("Expected 3 documented controls, got %d", delta.DocumentedCount)
	}
	if delta.ImplementedCount != 2 {
		t.Errorf("Expected 2 implemented controls, got %d", delta.ImplementedCount)
	}

	// Active Coverage: C3
	if len(delta.ActiveCoverage) != 1 || delta.ActiveCoverage[0] != "C3" {
		t.Errorf("Expected ActiveCoverage [C3], got %v", delta.ActiveCoverage)
	}

	// Policy Gap: C1, C2
	if len(delta.PolicyGap) != 2 {
		t.Errorf("Expected 2 PolicyGap controls, got %d", len(delta.PolicyGap))
	}

	// Implemented Only: C4
	if len(delta.ImplementedOnly) != 1 || delta.ImplementedOnly[0] != "C4" {
		t.Errorf("Expected ImplementedOnly [C4], got %v", delta.ImplementedOnly)
	}
}

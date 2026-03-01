// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"testing"

	"github.com/had-nu/wardex/pkg/catalog"
)

func TestCatalogLoad(t *testing.T) {
	controls := catalog.Load("iso27001")

	if len(controls) != 93 {
		t.Errorf("expected 93 controls, got %d", len(controls))
	}

	for _, c := range controls {
		if c.BaseScore < 0.0 || c.BaseScore > 10.0 {
			t.Errorf("control %s base_score %f out of bounds", c.ID, c.BaseScore)
		}

		if c.ID == "A.8.8" {
			foundGateRelevant := false
			for _, p := range c.Practices {
				if p.GateRelevant {
					foundGateRelevant = true
				}
			}
			if !foundGateRelevant {
				t.Errorf("expected A.8.8 to have at least one GateRelevant practice")
			}
		}
	}
}

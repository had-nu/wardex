// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"fmt"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

// EvaluateCoverage determines if the set of mapped controls fully covers the AnnexA control.
// The criteria for "covered": >=1 with high confidence AND maturity >= 3 AND evidence provided.
func EvaluateCoverage(maps []model.Mapping, controls []model.ExistingControl) (model.CoverageStatus, []string) {
	var reasons []string

	hasImplemented := false
	hasHighConfidence := false
	hasMaturity := false
	hasEvidence := false

	// Detail exactly what is failing across *all* mapped controls
	for _, m := range maps {
		var ec *model.ExistingControl
		for i := range controls {
			if controls[i].ID == m.ExistingControlID {
				ec = &controls[i]
				break
			}
		}

		if ec == nil {
			ui.Warnf("Mapping references nonexistent control %s — skipped", m.ExistingControlID)
			continue
		}

		if ec.Layer == model.LayerImplemented {
			hasImplemented = true

			if m.Confidence == "high" {
				hasHighConfidence = true
			} else {
				reasons = append(reasons, fmt.Sprintf("Control '%s' (implemented) has an inferred match only (low confidence)", ec.ID))
			}

			if ec.Maturity >= 3 {
				hasMaturity = true
			} else {
				reasons = append(reasons, fmt.Sprintf("Control '%s' (implemented) has maturity %d (minimum 3 required)", ec.ID, ec.Maturity))
			}

			if len(ec.Evidences) > 0 {
				hasEvidence = true
			} else {
				reasons = append(reasons, fmt.Sprintf("Control '%s' (implemented) has no declared evidence", ec.ID))
			}
		} else {
			reasons = append(reasons, fmt.Sprintf("Control '%s' is documented only (Paper Security)", ec.ID))
		}
	}

	if hasImplemented && hasHighConfidence && hasMaturity && hasEvidence {
		return model.StatusCovered, nil
	}

	if !hasHighConfidence && len(reasons) == 0 {
		reasons = append(reasons, "No correlation with high confidence")
	}

	return model.StatusPartial, reasons
}

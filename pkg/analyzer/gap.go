// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"fmt"

	"github.com/had-nu/wardex/pkg/model"
)

// EvaluateCoverage determines if the set of mapped controls fully covers the AnnexA control.
// The criteria for "covered": >=1 with high confidence AND maturity >= 3 AND evidence provided.
func EvaluateCoverage(maps []model.Mapping, controls []model.ExistingControl) (model.CoverageStatus, []string) {
	var reasons []string

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
			continue
		}

		if m.Confidence == "high" {
			hasHighConfidence = true
		} else {
			reasons = append(reasons, fmt.Sprintf("Controle '%s' tem matching inferido apenas (low confidence)", ec.ID))
		}

		if ec.Maturity >= 3 {
			hasMaturity = true
		} else {
			reasons = append(reasons, fmt.Sprintf("Controle '%s' tem maturidade %d (mínimo 3 exigido)", ec.ID, ec.Maturity))
		}

		if len(ec.Evidences) > 0 {
			hasEvidence = true
		} else {
			reasons = append(reasons, fmt.Sprintf("Controle '%s' não tem evidências declaradas", ec.ID))
		}
	}

	if hasHighConfidence && hasMaturity && hasEvidence {
		return model.StatusCovered, nil
	}

	if !hasHighConfidence && len(reasons) == 0 {
		reasons = append(reasons, "Nenhuma correlação com high confidence")
	}

	return model.StatusPartial, reasons
}

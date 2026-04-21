// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"testing"

	"github.com/had-nu/wardex/pkg/model"
)

func TestAssessPosture(t *testing.T) {
	findings := []model.Finding{
		{
			Control: model.CatalogControl{ID: "A.1", BaseScore: 10.0, Domain: "test"},
			Status:  model.StatusCovered,
		},
		{
			Control: model.CatalogControl{ID: "A.2", BaseScore: 10.0, Domain: "test"},
			Status:  model.StatusPartial,
		},
		{
			Control: model.CatalogControl{ID: "A.3", BaseScore: 10.0, Domain: "test"},
			Status:  model.StatusGap,
		},
	}

	a := &Analyzer{}
	report := a.AssessPosture(findings)

	// Math check:
	// Total Possible: 10 + 10 + 10 = 30
	// Achieved: 10 (Covered) + 5 (Partial) = 15
	// Index: (15 / 30) * 100 = 50.0
	if report.GlobalIndex != 50.0 {
		t.Errorf("Expected GlobalIndex 50.0, got %.1f", report.GlobalIndex)
	}

	// Exposure: 10.0 (Gap from A.3)
	if report.RiskExposure != 10.0 {
		t.Errorf("Expected RiskExposure 10.0, got %.1f", report.RiskExposure)
	}

	// Critical Gaps: A.3 should be there since BaseScore >= 7.0
	if len(report.CriticalGaps) != 1 || report.CriticalGaps[0].Control.ID != "A.3" {
		t.Errorf("Expected 1 critical gap (A.3), got %v", report.CriticalGaps)
	}
}

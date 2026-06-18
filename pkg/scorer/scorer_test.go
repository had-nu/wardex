// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer_test

import (
	"testing"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/scorer"
)

func TestScoreFormula(t *testing.T) {
	annex := model.CatalogControl{BaseScore: 5.0}

	// Case 1: Gap
	// score = BaseScore × weight × 1.0 (implementedCoverage = 0)
	score := scorer.Score(annex, nil, nil, model.StatusGap)
	if score != 5.0 {
		t.Errorf("Gap: expected score 5.0, got %f", score)
	}

	// Case 2: Gap with high ContextWeight
	extHigh := model.ExistingControl{ID: "C1", ContextWeight: 1.8}
	score = scorer.Score(annex, []model.Mapping{{ExistingControlID: "C1"}}, []model.ExistingControl{extHigh}, model.StatusGap)
	// 5.0 * 1.8 * 1.0 = 9.0
	if score != 9.0 {
		t.Errorf("Gap with weight: expected score 9.0, got %f", score)
	}

	// Case 3: Partial (Paper Security)
	// base_score=5, weight=1.0, status=partial -> 5 * 1.0 * (1 - 0.5) = 2.5
	score = scorer.Score(annex, nil, nil, model.StatusPartial)
	if score != 2.5 {
		t.Errorf("Partial: expected score 2.5, got %f", score)
	}

	// Case 4: Partial with Effectiveness
	// base_score=5, weight=1.0, status=partial, effectiveness=0.80
	// implementedCoverage = 0.5 * 0.8 = 0.4
	// score = 5 * 1.0 * (1 - 0.4) = 3.0
	extEff := model.ExistingControl{ID: "C2", Layer: model.LayerImplemented, Effectiveness: 0.8}
	score = scorer.Score(annex, []model.Mapping{{ExistingControlID: "C2"}}, []model.ExistingControl{extEff}, model.StatusPartial)
	if score != 3.0 {
		t.Errorf("Partial with effectiveness: expected score 3.0, got %f", score)
	}

	// Case 5: Covered (Full Effectiveness)
	// score = 5 * 1.0 * (1 - 1.0) = 0.0
	score = scorer.Score(annex, nil, nil, model.StatusCovered)
	if score != 0.0 {
		t.Errorf("Covered: expected score 0.0, got %f", score)
	}

	// Case 6: Covered with low Effectiveness
	// base_score=5, weight=1.0, status=covered, effectiveness=0.5
	// implementedCoverage = 1.0 * 0.5 = 0.5
	// score = 5 * 1.0 * (1 - 0.5) = 2.5
	extLowEff := model.ExistingControl{ID: "C3", Layer: model.LayerImplemented, Effectiveness: 0.5}
	score = scorer.Score(annex, []model.Mapping{{ExistingControlID: "C3"}}, []model.ExistingControl{extLowEff}, model.StatusCovered)
	if score != 2.5 {
		t.Errorf("Covered with low effectiveness: expected score 2.5, got %f", score)
	}
}

func TestMaturityByDomain(t *testing.T) {
	findings := []model.Finding{
		{Control: model.CatalogControl{Domain: "technological"}, Status: model.StatusCovered},
		{Control: model.CatalogControl{Domain: "technological"}, Status: model.StatusGap},
		{Control: model.CatalogControl{Domain: "organizational"}, Status: model.StatusPartial},
	}

	summaries := scorer.MaturityByDomain(findings)
	if len(summaries) != 4 {
		t.Fatalf("expected 4 domains, got %d", len(summaries))
	}

	for _, s := range summaries {
		if s.Domain == "technological" {
			if s.TotalControls != 2 || s.CoveredCount != 1 || s.CoveragePercent != 50.0 {
				t.Errorf("incorrect technological stats: %+v", s)
			}
		}
		if s.Domain == "organizational" {
			if s.TotalControls != 1 || s.PartialCount != 1 || s.CoveragePercent != 0.0 {
				t.Errorf("incorrect organizational stats: %+v", s)
			}
		}
	}
}

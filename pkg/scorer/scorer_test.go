// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer_test

import (
	"testing"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/scorer"
)

func TestScoreWeightClamping(t *testing.T) {
	annex := model.CatalogControl{BaseScore: 5.0}

	// Test high clamping
	extHigh := model.ExistingControl{ID: "C1", ContextWeight: 3.0}
	score := scorer.Score(annex, []model.Mapping{{ExistingControlID: "C1"}}, []model.ExistingControl{extHigh})
	// Weight should be clamped to 2.0 -> 5.0 * 2.0 = 10.0
	if score != 10.0 {
		t.Errorf("expected score 10.0 due to upper clamping, got %f", score)
	}

	// Test low clamping
	extLow := model.ExistingControl{ID: "C2", ContextWeight: 0.1}
	score = scorer.Score(annex, []model.Mapping{{ExistingControlID: "C2"}}, []model.ExistingControl{extLow})
	// Weight should be clamped to 0.5 -> 5.0 * 0.5 = 2.5
	if score != 2.5 {
		t.Errorf("expected score 2.5 due to lower clamping, got %f", score)
	}

	// Test valid range
	extValid := model.ExistingControl{ID: "C3", ContextWeight: 1.5}
	score = scorer.Score(annex, []model.Mapping{{ExistingControlID: "C3"}}, []model.ExistingControl{extValid})
	// 5.0 * 1.5 = 7.5
	if score != 7.5 {
		t.Errorf("expected score 7.5, got %f", score)
	}

	// Test missing control (defaults to 1.0)
	score = scorer.Score(annex, []model.Mapping{}, nil)
	if score != 5.0 {
		t.Errorf("expected score 5.0, got %f", score)
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

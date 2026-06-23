// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer_test

import (
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/analyzer"
	"github.com/had-nu/wardex/v2/pkg/model"
)

func TestAnalyzer_Covered(t *testing.T) {
	cat := []model.CatalogControl{{ID: "A.1", BaseScore: 5.0}}

	controls := []model.ExistingControl{
		{
			ID: "C1", Maturity: 3, Layer: model.LayerImplemented,
			Evidences: []model.Evidence{{Type: "policy", Ref: "link"}},
		},
	}

	maps := []model.Mapping{
		{ExistingControlID: "C1", CatalogControlID: "A.1", Confidence: "high"},
	}

	a := analyzer.New(cat, maps, controls)
	findings, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding")
	}

	if findings[0].Status != model.StatusCovered {
		t.Errorf("expected status covered, got %s", findings[0].Status)
	}
}

func TestAnalyzer_Partial_LowConfidence(t *testing.T) {
	cat := []model.CatalogControl{{ID: "A.1", BaseScore: 5.0}}

	controls := []model.ExistingControl{
		{
			ID: "C1", Maturity: 4, Layer: model.LayerImplemented,
			Evidences: []model.Evidence{{Type: "policy", Ref: "link"}},
		},
	}

	maps := []model.Mapping{
		{ExistingControlID: "C1", CatalogControlID: "A.1", Confidence: "low"},
	}

	a := analyzer.New(cat, maps, controls)
	findings, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if findings[0].Status != model.StatusPartial {
		t.Errorf("expected status partial, got %s", findings[0].Status)
	}

	if len(findings[0].GapReasons) == 0 || !strings.Contains(findings[0].GapReasons[0], "low confidence") {
		t.Errorf("expected low confidence reason, got %v", findings[0].GapReasons)
	}
}

func TestAnalyzer_Gap(t *testing.T) {
	cat := []model.CatalogControl{{ID: "A.1", BaseScore: 5.0}}

	a := analyzer.New(cat, nil, nil)
	findings, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if findings[0].Status != model.StatusGap {
		t.Errorf("expected status gap, got %s", findings[0].Status)
	}
}

func TestAnalyzer_EffectiveMaturity(t *testing.T) {
	cat := []model.CatalogControl{{ID: "A.1"}}
	controls := []model.ExistingControl{
		{ID: "C1", Maturity: 2},
		{ID: "C2", Maturity: 4},
	}
	maps := []model.Mapping{
		{ExistingControlID: "C1", CatalogControlID: "A.1"},
		{ExistingControlID: "C2", CatalogControlID: "A.1"},
	}

	a := analyzer.New(cat, maps, controls)
	findings, _ := a.Analyze()

	// EffectiveMaturity = (2 + 4) / 2 = 3.0
	if findings[0].EffectiveMaturity != 3.0 {
		t.Errorf("expected effective maturity 3.0, got %f", findings[0].EffectiveMaturity)
	}
}

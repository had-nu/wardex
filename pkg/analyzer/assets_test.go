// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"testing"

	"github.com/had-nu/wardex/pkg/model"
)

func TestAssessAssets(t *testing.T) {
	catalog := []model.CatalogControl{
		{ID: "A.5.1", Name: "Policies"},
		{ID: "A.8.8", Name: "Vulnerabilities"},
	}

	controls := []model.ExistingControl{
		{ID: "EC-1", Maturity: 3, Layer: model.LayerImplemented, Evidences: []model.Evidence{{Type: "link"}}},
		{ID: "EC-2", Maturity: 1, Layer: model.LayerImplemented}, // Low maturity, should not count as covered
	}

	mappings := []model.Mapping{
		{ExistingControlID: "EC-1", CatalogControlID: "A.5.1"},
		{ExistingControlID: "EC-2", CatalogControlID: "A.8.8"},
	}

	assets := []model.Asset{
		{
			ID:       "ASSET-001",
			Name:     "Prod Server",
			Controls: []string{"EC-1", "EC-2"},
		},
	}

	results := AssessAssets(assets, controls, catalog, mappings)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.AssetID != "ASSET-001" {
		t.Errorf("Expected AssetID ASSET-001, got %s", res.AssetID)
	}

	// Only A.5.1 is covered (EC-1 maturity 3 + evidence)
	// A.8.8 is NOT covered (EC-2 maturity 1)
	// Coverage = 1/2 = 0.5
	if res.ComplianceScore != 0.5 {
		t.Errorf("Expected ComplianceScore 0.5, got %f", res.ComplianceScore)
	}

	if len(res.MissingControls) != 1 || res.MissingControls[0] != "A.8.8" {
		t.Errorf("Expected MissingControls [A.8.8], got %v", res.MissingControls)
	}
}

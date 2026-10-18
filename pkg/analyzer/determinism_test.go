// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"slices"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// These lists are built by ranging over a map. Go randomises map iteration, so
// without an explicit sort two runs over identical evidence produced reports
// whose rows came out in a different order. That defeats the property the whole
// tool rests on: the same evidence must render the same report, because the
// report is the evidence.

func layerDeltaControls() []model.ExistingControl {
	return []model.ExistingControl{
		{ID: "DOC-ORG-004", Layer: model.LayerDocumented},
		{ID: "DOC-PPL-001", Layer: model.LayerDocumented},
		{ID: "DOC-TECH-002", Layer: model.LayerDocumented},
		{ID: "DOC-ORG-001", Layer: model.LayerDocumented},
		{ID: "DOC-TECH-005", Layer: model.LayerDocumented},
		{ID: "IMPL-TECH-009", Layer: model.LayerImplemented},
		{ID: "IMPL-ORG-003", Layer: model.LayerImplemented},
		{ID: "DOC-PPL-004", Layer: model.LayerDocumented},
		{ID: "IMPL-TECH-011", Layer: model.LayerImplemented},
		{ID: "DOC-ORG-005", Layer: model.LayerDocumented},
	}
}

func TestComputeLayerDeltaIsOrderStable(t *testing.T) {
	run := func() model.LayerDelta {
		a := &Analyzer{Controls: layerDeltaControls()}
		return a.ComputeLayerDelta()
	}

	first := run()
	for _, list := range [][]string{first.ActiveCoverage, first.PolicyGap, first.ImplementedOnly} {
		if !slices.IsSorted(list) {
			t.Fatalf("layer delta list is not sorted: %v", list)
		}
	}

	// One iteration is normally enough to expose map randomness; repeat so a
	// single unlucky draw cannot mask a regression.
	for i := range 500 {
		got := run()
		if !slices.Equal(got.ActiveCoverage, first.ActiveCoverage) ||
			!slices.Equal(got.PolicyGap, first.PolicyGap) ||
			!slices.Equal(got.ImplementedOnly, first.ImplementedOnly) {
			t.Fatalf("run %d differs from the first run\nfirst: %+v\ngot:   %+v", i, first, got)
		}
	}
}

func TestComputeLayerDeltaCountsUnchanged(t *testing.T) {
	a := &Analyzer{Controls: layerDeltaControls()}
	delta := a.ComputeLayerDelta()

	if delta.DocumentedCount != 7 {
		t.Errorf("DocumentedCount = %d, want 7", delta.DocumentedCount)
	}
	if delta.ImplementedCount != 3 {
		t.Errorf("ImplementedCount = %d, want 3", delta.ImplementedCount)
	}
	// Sorting must not drop or duplicate entries.
	if len(delta.PolicyGap)+len(delta.ActiveCoverage) != delta.DocumentedCount {
		t.Errorf("documented controls split as %d gap + %d active, want %d total",
			len(delta.PolicyGap), len(delta.ActiveCoverage), delta.DocumentedCount)
	}
	if len(delta.ImplementedOnly) != 3 {
		t.Errorf("ImplementedOnly = %v, want 3 entries", delta.ImplementedOnly)
	}
}

func assetComplianceInputs() ([]model.Asset, []model.ExistingControl, []model.CatalogControl, []model.Mapping) {
	const catalogSize = 24

	catalog := make([]model.CatalogControl, 0, catalogSize)
	mappings := make([]model.Mapping, 0, catalogSize)
	for i := range catalogSize {
		catalogID := "A." + string(rune('1'+i/10)) + string(rune('1'+i%10))
		catalog = append(catalog, model.CatalogControl{ID: catalogID, Domain: "technological"})

		// One existing control per catalog control, wired through a mapping.
		mappings = append(mappings, model.Mapping{
			ExistingControlID: "EX-" + catalogID,
			CatalogControlID:  catalogID,
			Confidence:        "high",
		})
	}

	// Each asset implements only some of them, so both end up with a sizeable
	// missing-controls list built from a map.
	implemented := []model.ExistingControl{
		{ID: "EX-A.11", Layer: model.LayerImplemented},
		{ID: "EX-A.21", Layer: model.LayerImplemented},
	}
	assets := []model.Asset{
		{ID: "asset-1", Name: "one", Controls: []string{"EX-A.11"}},
		{ID: "asset-2", Name: "two", Controls: []string{"EX-A.11", "EX-A.21"}},
	}
	return assets, implemented, catalog, mappings
}

func TestAssessAssetsMissingControlsAreSorted(t *testing.T) {
	assets, controls, catalog, mappings := assetComplianceInputs()

	run := func() []model.AssetCompliance {
		return AssessAssets(assets, controls, catalog, mappings)
	}

	first := run()
	if len(first) != len(assets) {
		t.Fatalf("got %d results, want %d", len(first), len(assets))
	}
	for i, ac := range first {
		if len(ac.MissingControls) < 2 {
			t.Fatalf("asset %d has %d missing controls; the fixture needs more to be meaningful",
				i, len(ac.MissingControls))
		}
		if !slices.IsSorted(ac.MissingControls) {
			t.Fatalf("asset %d missing controls are not sorted: %v", i, ac.MissingControls)
		}
	}

	for i := range 300 {
		got := run()
		for j := range got {
			if !slices.Equal(got[j].MissingControls, first[j].MissingControls) {
				t.Fatalf("run %d asset %d missing controls differ\nfirst: %v\ngot:   %v",
					i, j, first[j].MissingControls, got[j].MissingControls)
			}
		}
	}
}

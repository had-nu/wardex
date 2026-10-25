// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer_test

import (
	"testing"

	"github.com/had-nu/wardex/v3/pkg/analyzer"
	"github.com/had-nu/wardex/v3/pkg/catalog"
	"github.com/had-nu/wardex/v3/pkg/correlator"
	"github.com/had-nu/wardex/v3/pkg/model"
)

// TestGDPRImplementedControlReachesCovered is the end-to-end test for M0-P0.2.
//
// A control implemented at maturity 4, with evidence and a domain that matches
// the catalogue, must reach Covered. Before the loader derived Domains from
// Domain, the GDPR catalogue control had no declared domains, so the correlation
// was only inferential (low confidence) and EvaluateCoverage kept the finding
// at Partial even though the implementation was complete.
func TestGDPRImplementedControlReachesCovered(t *testing.T) {
	controls, err := catalog.Load("gdpr")
	if err != nil {
		t.Fatalf("Load(gdpr): %v", err)
	}

	var target model.CatalogControl
	for _, c := range controls {
		if c.Domain != "" {
			target = c
			break
		}
	}
	if target.ID == "" {
		t.Fatal("no GDPR control declares a domain")
	}

	existing := []model.ExistingControl{{
		ID:        "CTRL-1",
		Domains:   []string{target.Domain},
		Maturity:  4,
		Layer:     model.LayerImplemented,
		Evidences: []model.Evidence{{Type: "policy", Ref: "evidence.md"}},
	}}

	mappings, err := correlator.New([]model.CatalogControl{target}).Correlate(existing)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("expected one mapping to %s, got %d", target.ID, len(mappings))
	}
	if mappings[0].Confidence != "high" {
		t.Fatalf("mapping to %s has confidence %q; want high", target.ID, mappings[0].Confidence)
	}

	findings, err := analyzer.New([]model.CatalogControl{target}, mappings, existing).Analyze()
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Status != model.StatusCovered {
		t.Fatalf("finding %s is %s, gap reasons: %v; want covered",
			target.ID, findings[0].Status, findings[0].GapReasons)
	}
}

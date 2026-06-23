// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"fmt"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/scorer"
)

// Analyzer performs compliance gap analysis against a framework catalog.
type Analyzer struct {
	Catalog  []model.CatalogControl
	Mappings []model.Mapping
	Controls []model.ExistingControl
}

// New creates a new Analyzer with the given catalog, control mappings, and existing controls.
func New(catalog []model.CatalogControl, mappings []model.Mapping, controls []model.ExistingControl) *Analyzer {
	return &Analyzer{
		Catalog:  catalog,
		Mappings: mappings,
		Controls: controls,
	}
}

// Analyze processes mappings and produces coverage findings for each framework control.
// Returns a slice of Findings representing the compliance status of each control.
func (a *Analyzer) Analyze() ([]model.Finding, error) {
	if len(a.Catalog) == 0 {
		return nil, fmt.Errorf("analyzer: empty catalog")
	}

	var findings []model.Finding

	mappingByAnnex := make(map[string][]model.Mapping)
	for _, m := range a.Mappings {
		mappingByAnnex[m.CatalogControlID] = append(mappingByAnnex[m.CatalogControlID], m)
	}

	for _, anx := range a.Catalog {
		maps := mappingByAnnex[anx.ID]

		var status model.CoverageStatus
		var reasons []string
		var effectiveMaturity float64

		if len(maps) == 0 {
			status = model.StatusGap
			reasons = append(reasons, "Nenhuma correlação encontrada")
		} else {
			status, reasons = EvaluateCoverage(maps, a.Controls)

			// Calculate EffectiveMaturity: arithmetic mean of mapped controls' maturity
			var sum int
			var count int
			for _, m := range maps {
				for _, ec := range a.Controls {
					if ec.ID == m.ExistingControlID {
						sum += ec.Maturity
						count++
						break
					}
				}
			}
			if count > 0 {
				effectiveMaturity = float64(sum) / float64(count)
			}
		}

		// Score calculated after status is resolved.
		finalScore := scorer.Score(anx, maps, a.Controls, status)

		finding := model.Finding{
			Control:           anx,
			Status:            status,
			FinalScore:        finalScore,
			EffectiveMaturity: effectiveMaturity,
			CoveredBy:         maps,
			GapReasons:        reasons,
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// AnalyzeWithConfig performs analysis with additional configuration options.
func (a *Analyzer) AnalyzeWithConfig(opts *AnalyzerOptions) ([]model.Finding, error) {
	opts.setDefaults()
	if opts.FilterLowConfidence {
		var filtered []model.Mapping
		for _, m := range a.Mappings {
			if m.Confidence == "high" {
				filtered = append(filtered, m)
			}
		}
		a.Mappings = filtered
	}
	return a.Analyze()
}

// AnalyzerOptions provides configuration for AnalyzeWithConfig.
type AnalyzerOptions struct {
	FilterLowConfidence bool
	MinMaturity         int
}

func (o *AnalyzerOptions) setDefaults() {
	if o == nil {
		*o = AnalyzerOptions{}
	}
}

// ComputeLayerDelta analyzes the difference between documented and implemented controls.
func (a *Analyzer) ComputeLayerDelta() model.LayerDelta {
	docSet := make(map[string]bool)
	impSet := make(map[string]bool)

	for _, c := range a.Controls {
		if c.Layer == model.LayerDocumented {
			docSet[c.ID] = true
		} else if c.Layer == model.LayerImplemented {
			impSet[c.ID] = true
		}
	}

	delta := model.LayerDelta{
		DocumentedCount:  len(docSet),
		ImplementedCount: len(impSet),
	}

	for id := range docSet {
		if impSet[id] {
			delta.ActiveCoverage = append(delta.ActiveCoverage, id)
		} else {
			delta.PolicyGap = append(delta.PolicyGap, id) // Documented but not implemented
		}
	}

	for id := range impSet {
		if !docSet[id] {
			delta.ImplementedOnly = append(delta.ImplementedOnly, id) // Implemented but not documented
		}
	}

	return delta
}

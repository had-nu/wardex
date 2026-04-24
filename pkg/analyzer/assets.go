// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"time"

	"github.com/had-nu/wardex/pkg/model"
)

// AssessAssets performs context-aware compliance assessment for a list of assets.
// It maps asset-linked controls to the framework catalog and calculates a coverage score.
func AssessAssets(assets []model.Asset, controls []model.ExistingControl, catalog []model.CatalogControl, mappings []model.Mapping) []model.AssetCompliance {
	var results []model.AssetCompliance

	// Index controls for quick lookup. If multiple layers exist for the same ID,
	// we keep both or prioritize the implemented one for compliance checking.
	controlMap := make(map[string][]model.ExistingControl)
	for _, c := range controls {
		controlMap[c.ID] = append(controlMap[c.ID], c)
	}

	// Index mappings by ExistingControlID
	controlToCatalog := make(map[string][]string)
	for _, m := range mappings {
		controlToCatalog[m.ExistingControlID] = append(controlToCatalog[m.ExistingControlID], m.CatalogControlID)
	}

	for _, asset := range assets {
		compliance := model.AssetCompliance{
			AssetID:          asset.ID,
			AssetName:        asset.Name,
			LastAssessmentAt: time.Now(),
		}

		// Required controls are those in the catalog.
		// If asset.Scope is defined, we could filter the catalog, but for now
		// we assume the provided catalog is the target framework.
		requiredIDs := make(map[string]bool)
		for _, cat := range catalog {
			requiredIDs[cat.ID] = true
		}

		// Implemented controls for this asset
		implementedMap := make(map[string]bool)
		for _, ctrlID := range asset.Controls {
			if catIDs, ok := controlToCatalog[ctrlID]; ok {
				for _, catID := range catIDs {
					// A control counts as implemented for the asset if:
					// 1. It is in the Implemented layer
					// 2. It passes basic coverage criteria (maturity >= 3, has evidence)
					if cs, ok := controlMap[ctrlID]; ok {
						for _, c := range cs {
							if c.Layer == model.LayerImplemented {
								// Simple check equivalent to EvaluateCoverage but per-control
								if c.Maturity >= 3 && len(c.Evidences) > 0 {
									implementedMap[catID] = true
								}
							}
						}
					}
				}
			}
		}

		coveredCount := 0
		for reqID := range requiredIDs {
			if implementedMap[reqID] {
				coveredCount++
			} else {
				compliance.MissingControls = append(compliance.MissingControls, reqID)
			}
		}

		if len(requiredIDs) > 0 {
			compliance.ComplianceScore = float64(coveredCount) / float64(len(requiredIDs))
		} else {
			compliance.ComplianceScore = 1.0
		}

		// Set status based on score
		if compliance.ComplianceScore >= 1.0 {
			compliance.Status = "compliant"
		} else if compliance.ComplianceScore >= 0.6 {
			compliance.Status = "partial"
		} else {
			compliance.Status = "non_compliant"
		}

		results = append(results, compliance)
	}

	return results
}

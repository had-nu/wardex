// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer

import (
	"github.com/had-nu/wardex/pkg/model"
)

// Score calculates the roadmap priority score for a catalog control.
//
// Formula: BaseScore × ContextWeight × (1 − ImplementedCoverage) × EffectivenessFactor
//
// ImplementedCoverage:
//   - 1.0 if the control has at least one implemented-layer mapping (covered → exits roadmap)
//   - 0.5 if partial (documented but no implemented counterpart)
//   - 0.0 if gap (no mapping at all)
//
// EffectivenessFactor: mean effectiveness across implemented controls, default 1.0.
// A low-effectiveness implementation is treated as partial coverage, not full.
//
// ContextWeight: max declared context_weight across mapped controls, clamped [0.5, 2.0].
// Default 1.0 when absent.
func Score(
	annexControl model.CatalogControl,
	mappings []model.Mapping,
	controls []model.ExistingControl,
	status model.CoverageStatus,
) float64 {
	// ── ContextWeight ────────────────────────────────────────────────────────
	weight := 1.0
	maxWeight := 0.0
	for _, m := range mappings {
		for _, ec := range controls {
			if ec.ID == m.ExistingControlID && ec.ContextWeight > maxWeight {
				maxWeight = ec.ContextWeight
				break
			}
		}
	}
	if maxWeight > 0.0 {
		weight = maxWeight
	}
	if weight < 0.5 {
		weight = 0.5
	} else if weight > 2.0 {
		weight = 2.0
	}

	// ── ImplementedCoverage ──────────────────────────────────────────────────
	var implementedCoverage float64
	switch status {
	case model.StatusCovered:
		implementedCoverage = 1.0
	case model.StatusPartial:
		implementedCoverage = 0.5
	case model.StatusGap:
		implementedCoverage = 0.0
	}

	// ── EffectivenessFactor ──────────────────────────────────────────────────
	// Mean effectiveness across implemented-layer controls that map to this catalog entry.
	// Only implemented controls contribute — documented-only controls do not reduce risk.
	effectivenessSum := 0.0
	effectivenessCount := 0
	for _, m := range mappings {
		for _, ec := range controls {
			if ec.ID == m.ExistingControlID && ec.Layer == model.LayerImplemented {
				e := ec.Effectiveness
				if e <= 0.0 {
					e = 1.0 // absent field → full weight (backward compat)
				}
				effectivenessSum += e
				effectivenessCount++
				break
			}
		}
	}
	effectivenessFactor := 1.0
	if effectivenessCount > 0 {
		effectivenessFactor = effectivenessSum / float64(effectivenessCount)
	}

	// Adjust implementedCoverage by effectiveness:
	// a covered control with effectiveness 0.5 is treated as 50% covered.
	implementedCoverage *= effectivenessFactor

	// Priority score: high when gap (implementedCoverage → 0), zero when fully covered.
	return annexControl.BaseScore * weight * (1.0 - implementedCoverage)
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer

import (
	"github.com/had-nu/wardex/v2/pkg/model"
)

// MaturityByDomain calculates maturity scores aggregated by the 4 Annex A domains.
func MaturityByDomain(findings []model.Finding) []model.DomainSummary {
	domains := []string{"organizational", "people", "physical", "technological"}

	summaries := make(map[string]*model.DomainSummary)
	for _, d := range domains {
		summaries[d] = &model.DomainSummary{
			Domain:          d,
			TotalControls:   0,
			CoveredCount:    0,
			PartialCount:    0,
			GapCount:        0,
			MaturityScore:   0,
			CoveragePercent: 0,
		}
	}


	for _, f := range findings {
		d := f.Control.Domain
		s, ok := summaries[d]
		if !ok {
			continue // Should not happen if catalog is well-formed
		}

		s.TotalControls++

		switch f.Status {
		case model.StatusCovered:
			s.CoveredCount++
		case model.StatusPartial:
			s.PartialCount++
		case model.StatusGap:
			s.GapCount++
		}

		// Calculate maturity contribution using the v1.8.0 EffectiveMaturity
		s.MaturityScore += f.EffectiveMaturity
	}

	var result []model.DomainSummary
	for _, d := range domains {
		s := summaries[d]
		if s.TotalControls > 0 {
			s.CoveragePercent = float64(s.CoveredCount) / float64(s.TotalControls) * 100.0
			s.MaturityScore = s.MaturityScore / float64(s.TotalControls)
		}
		result = append(result, *s)
	}

	return result
}

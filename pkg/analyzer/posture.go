// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"sort"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// PostureReport provides high-level security posture intelligence metrics.
type PostureReport struct {
	GlobalIndex         float64        // Overall coverage score (0-100)
	RiskExposure        float64        // Sum of BaseScores for all identified gaps
	DomainConcentration map[string]int // Number of gaps per domain
	CriticalGaps        []model.Finding // High-impact controls with 'gap' status
}

// AssessPosture aggregates findings into an intelligence report.
func (a *Analyzer) AssessPosture(findings []model.Finding) PostureReport {
	report := PostureReport{
		DomainConcentration: make(map[string]int),
	}

	if len(findings) == 0 {
		return report
	}

	var totalPossibleScore float64
	var achievedScore float64

	for _, f := range findings {
		totalPossibleScore += f.Control.BaseScore

		switch f.Status {
		case model.StatusCovered:
			achievedScore += f.Control.BaseScore
		case model.StatusPartial:
			// Partial coverage provides 50% of the posture value
			achievedScore += (f.Control.BaseScore * 0.5)
		case model.StatusGap:
			report.RiskExposure += f.Control.BaseScore
			report.DomainConcentration[f.Control.Domain]++

			// Identify high-impact gaps (BaseScore >= 7.0)
			if f.Control.BaseScore >= 7.0 {
				report.CriticalGaps = append(report.CriticalGaps, f)
			}
		}
	}

	if totalPossibleScore > 0 {
		report.GlobalIndex = (achievedScore / totalPossibleScore) * 100.0
	}

	// Sort critical gaps by BaseScore descending
	sort.Slice(report.CriticalGaps, func(i, j int) bool {
		return report.CriticalGaps[i].Control.BaseScore > report.CriticalGaps[j].Control.BaseScore
	})

	return report
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer

import (
	"time"

	"github.com/had-nu/wardex/pkg/model"
)

// Summarize calculates global metrics from a list of findings.
func Summarize(findings []model.Finding) model.ExecutiveSummary {
	summary := model.ExecutiveSummary{
		GeneratedAt:   time.Now(),
		TotalControls: len(findings),
	}

	for _, f := range findings {
		switch f.Status {
		case model.StatusCovered:
			summary.CoveredCount++
		case model.StatusPartial:
			summary.PartialCount++
		default:
			summary.GapCount++
		}
	}

	if summary.TotalControls > 0 {
		summary.GlobalCoverage = float64(summary.CoveredCount) / float64(summary.TotalControls) * 100.0
	}

	return summary
}

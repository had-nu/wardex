// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package releasegate

import "github.com/had-nu/wardex/pkg/model"

// CalculateRisk generates a risk breakdown for a single vulnerability in context.
func CalculateRisk(vuln model.Vulnerability, ctx model.AssetContext, comps []model.CompensatingControl) model.RiskBreakdown {
	epss := vuln.EPSSScore
	if epss == 0.0 {
		epss = 1.0
	}
	adjusted := vuln.CVSSBase * epss

	internetWeight := 0.6
	if ctx.InternetFacing {
		internetWeight = 1.0
	} else if ctx.Environment == "development" {
		internetWeight = 0.3
	}

	authRed := 0.0
	if ctx.RequiresAuth {
		authRed = 0.2
	}
	reachableRed := 0.0
	if !vuln.Reachable {
		reachableRed = 0.5
	}

	exposure := internetWeight * (1 - authRed) * (1 - reachableRed)

	compEffect := 0.0
	for _, c := range comps {
		compEffect += c.Effectiveness
	}
	if compEffect > 0.8 {
		compEffect = 0.8
	}

	compensatedScore := adjusted * (1 - compEffect)

	criticality := ctx.Criticality
	if criticality == 0.0 {
		criticality = 1.0
	}

	finalRisk := compensatedScore * criticality * exposure

	return model.RiskBreakdown{
		CVSSBase:           vuln.CVSSBase,
		EPSSFactor:         epss,
		AdjustedScore:      adjusted,
		AssetCriticality:   criticality,
		ExposureFactor:     exposure,
		CompensatingEffect: compEffect,
		FinalReleaseRisk:   finalRisk,
	}
}

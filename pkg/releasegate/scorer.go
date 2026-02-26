package releasegate

import "github.com/had-nu/wardex/pkg/model"

// CalculateRisk generates a risk breakdown for a single vulnerability in context.
func CalculateRisk(vuln model.Vulnerability, ctx model.AssetContext, comps []model.CompensatingControl) model.RiskBreakdown {
	// Adjusted Score
	epss := vuln.EPSSScore
	if epss == 0.0 {
		epss = 1.0 // Conservative default
	}
	adjusted := vuln.CVSSBase * epss

	// Exposure Factor
	internetWeight := 0.6 // Internal default
	if ctx.InternetFacing {
		internetWeight = 1.0
	} else if ctx.Environment == "development" {
		internetWeight = 0.3 // Roughly air-gapped / development
	}

	authRed := 0.0
	if ctx.RequiresAuth {
		authRed = 0.2
	}
	// "auth_reduction \u2208 [0.0, 0.4] — redução de exposição quando autenticação é exigida"

	reachableRed := 0.0
	if !vuln.Reachable {
		reachableRed = 0.5 // Massive reduction if unreachable
	}

	exposure := internetWeight * (1 - authRed) * (1 - reachableRed)

	// Compensating Controls
	compEffect := 0.0
	for _, c := range comps {
		compEffect += c.Effectiveness
	}
	if compEffect > 0.8 {
		compEffect = 0.8 // Clamped at 0.8
	}

	compensatedScore := adjusted * (1 - compEffect)

	criticality := ctx.Criticality
	if criticality == 0.0 {
		criticality = 1.0 // Conservative limit
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

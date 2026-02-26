package releasegate

import (
	"fmt"

	"github.com/had-nu/wardex/pkg/model"
)

// Gate evaluates vulnerabilities and orchestrates release decisions.
type Gate struct {
	AssetContext         model.AssetContext
	CompensatingControls []model.CompensatingControl
	RiskAppetite         float64
	Mode                 string // "any" | "aggregate"
}

// Evaluate performs compound risk analysis on all vulnerabilitles and returns the GateReport.
func (g *Gate) Evaluate(vulns []model.Vulnerability) model.GateReport {
	report := model.GateReport{
		GateMaturityLevel: InferMaturityLevel(g.AssetContext, g.CompensatingControls),
		OverallDecision:   "allow",
	}

	var totalRisk float64
	var highestRisk float64

	for _, v := range vulns {
		brk := CalculateRisk(v, g.AssetContext, g.CompensatingControls)

		decisionStr := "allow"
		if brk.FinalReleaseRisk > g.RiskAppetite && g.Mode != "aggregate" {
			decisionStr = "block"
			report.BlockedCount++
			report.OverallDecision = "block"
		} else {
			report.AllowedCount++
		}

		if brk.FinalReleaseRisk > highestRisk {
			highestRisk = brk.FinalReleaseRisk
		}

		totalRisk += brk.FinalReleaseRisk

		trail := fmt.Sprintf("[%s] %s — release_risk: %.1f, cvss_adjusted: %.1f, exposure: %.2f",
			decisionStr, v.CVEID, brk.FinalReleaseRisk, brk.AdjustedScore, brk.ExposureFactor)

		report.Decisions = append(report.Decisions, model.ReleaseDecision{
			Vulnerability: v,
			ReleaseRisk:   brk.FinalReleaseRisk,
			RiskAppetite:  g.RiskAppetite,
			Decision:      decisionStr,
			Breakdown:     brk,
			AuditTrail:    trail,
		})
	}

	report.HighestRisk = highestRisk

	if g.Mode == "aggregate" && totalRisk > g.RiskAppetite {
		report.OverallDecision = "block"
	}

	return report
}

package releasegate_test

import (
	"testing"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
)

func TestRiskBasedGateVsBinaryThreshold(t *testing.T) {
	vuln := model.Vulnerability{
		CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true,
	}

	// Contexto de baixo risco: ferramenta interna, air-gapped, controles fortes
	lowRiskGate := releasegate.Gate{
		AssetContext: model.AssetContext{
			Criticality: 0.2, InternetFacing: false, RequiresAuth: true, Environment: "development",
		},
		CompensatingControls: []model.CompensatingControl{
			{Type: "network_segmentation", Effectiveness: 0.7},
			{Type: "runtime_protection", Effectiveness: 0.5},
		},
		RiskAppetite: 6.0,
	}

	// Contexto de alto risco: sistema financeiro exposto, sem compensação
	highRiskGate := releasegate.Gate{
		AssetContext: model.AssetContext{
			Criticality: 0.9, InternetFacing: true, RequiresAuth: false,
		},
		CompensatingControls: []model.CompensatingControl{},
		RiskAppetite:         6.0,
	}

	lowReport := lowRiskGate.Evaluate([]model.Vulnerability{vuln})
	highReport := highRiskGate.Evaluate([]model.Vulnerability{vuln})

	if lowReport.OverallDecision != "allow" {
		t.Errorf("esperado allow em contexto de baixo risco, got: %s (risk score: %f)", lowReport.OverallDecision, lowReport.Decisions[0].ReleaseRisk)
	}
	if highReport.OverallDecision != "block" {
		t.Errorf("esperado block em contexto de alto risco, got: %s (risk score: %f)", highReport.OverallDecision, highReport.Decisions[0].ReleaseRisk)
	}
}

func TestGateMaturityInference(t *testing.T) {
	cases := []struct {
		ctx      model.AssetContext
		controls []model.CompensatingControl
		minLevel int
	}{
		{model.AssetContext{Criticality: 0.5}, nil, 1},
		{model.AssetContext{Criticality: 0.5, InternetFacing: true}, nil, 2},
		{model.AssetContext{Criticality: 0.5, InternetFacing: true, RequiresAuth: true}, nil, 3},
		{
			model.AssetContext{Criticality: 0.9, InternetFacing: true, RequiresAuth: true},
			[]model.CompensatingControl{{Type: "waf", Effectiveness: 0.3}},
			4,
		},
	}
	for _, tc := range cases {
		level := releasegate.InferMaturityLevel(tc.ctx, tc.controls)
		if level < tc.minLevel {
			t.Errorf("esperado nível >= %d, got %d", tc.minLevel, level)
		}
	}
}

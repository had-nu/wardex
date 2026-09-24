// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/orchestrator"
)

func TestBuildGateDashboardMapsDecisions(t *testing.T) {
	opts := orchestrator.GateOptions{
		Controls:     []string{"controls.yml"},
		GateFile:     "evidence.yml",
		ConfigPath:   "config.yml",
		GateMode:     "any",
		GateClass:    "deploy",
		OutputFormat: "json",
	}
	report := model.GateReport{
		OverallDecision:   model.DecisionBlock,
		BlockedCount:      1,
		AllowedCount:      2,
		WarnCount:         1,
		HighestRisk:       0.91,
		GateMaturityLevel: 4,
		Decisions: []model.ReleaseDecision{{
			Vulnerability: model.Vulnerability{
				CVEID:     "CVE-TEST-1",
				Component: "example:1.0",
				CVSSBase:  9.8,
				EPSSScore: 0.8,
				Reachable: true,
			},
			ReleaseRisk: 0.91,
			Decision:    model.DecisionBlock,
		}},
	}

	dashboard := buildGateDashboard(opts, report)
	if dashboard.Session.Title != "RELEASE GATE SESSION" {
		t.Fatalf("unexpected session title: %q", dashboard.Session.Title)
	}
	if len(dashboard.Findings) != 1 {
		t.Fatalf("expected one decision card, got %d", len(dashboard.Findings))
	}
	card := dashboard.Findings[0]
	if card.Kind != "RELEASE GATE DECISION" || card.Severity != "HIGH" {
		t.Fatalf("unexpected decision card: %+v", card)
	}
	if dashboard.Summary.Decision != "BLOCK" {
		t.Fatalf("unexpected summary decision: %q", dashboard.Summary.Decision)
	}
}

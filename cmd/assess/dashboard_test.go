// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package assess

import (
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

func TestBuildAssessDashboardMapsReport(t *testing.T) {
	session := ui.SessionView{
		Title:  "ASSESSMENT SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{{Label: "INPUT", Value: "controls.yml"}},
	}
	finding := model.Finding{
		Control:    model.CatalogControl{ID: "A.5.15", Name: "Access control"},
		Status:     model.StatusGap,
		FinalScore: 0.91,
		CoveredBy:  []model.Mapping{{Confidence: "medium"}, {Confidence: "high"}},
	}
	report := model.GapReport{
		Summary: model.ExecutiveSummary{
			TotalControls:  10,
			CoveredCount:   6,
			PartialCount:   2,
			GapCount:       2,
			GlobalCoverage: 60,
		},
		Findings: []model.Finding{finding},
		Roadmap:  []model.Finding{finding},
		LayerDelta: &model.LayerDelta{
			DocumentedCount:  5,
			ImplementedCount: 4,
		},
	}

	dashboard := buildAssessDashboard(session, report, "iso27001")
	if dashboard.Session.Status != "COMPLETE" {
		t.Fatalf("unexpected session status: %q", dashboard.Session.Status)
	}
	if len(dashboard.Findings) != 1 {
		t.Fatalf("expected one finding card, got %d", len(dashboard.Findings))
	}
	card := dashboard.Findings[0]
	if card.Kind != "COMPLIANCE GAP" || card.Severity != "HIGH" || card.Confidence != "HIGH" {
		t.Fatalf("unexpected finding card: %+v", card)
	}
	if dashboard.Summary.Decision != "COMPLETE" {
		t.Fatalf("unexpected summary decision: %q", dashboard.Summary.Decision)
	}
}

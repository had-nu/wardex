// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/orchestrator"
)

func TestBuildEvaluationDashboardMapsCoreFields(t *testing.T) {
	finding := model.Finding{
		Control:        model.CatalogControl{ID: "A.5.15", Name: "Access control policy"},
		Status:         model.StatusGap,
		FinalScore:     0.92,
		CoveredBy:      []model.Mapping{{Confidence: "high"}},
		GapReasons:     []string{"evidence missing"},
		Recommendation: "assign an owner",
	}
	report := model.GapReport{
		Summary: model.ExecutiveSummary{
			TotalControls:  10,
			CoveredCount:   7,
			PartialCount:   1,
			GapCount:       2,
			GlobalCoverage: 70,
		},
		Findings: []model.Finding{finding},
		Roadmap:  []model.Finding{finding},
	}

	opts := orchestrator.EvaluationOptions{
		Inputs:        []string{"controls.yml"},
		Framework:     "iso27001",
		ProfileName:   "strict",
		OutputFormat:  "json",
		MinConfidence: "high",
		SnapshotFile:  ".wardex.json",
		RoadmapLimit:  10,
	}
	result := &orchestrator.EvaluationResult{
		Report:     report,
		ExitCode:   11,
		ExitReason: orchestrator.ExitCompliance,
	}

	dashboard := buildEvaluationDashboard(opts, result)
	if dashboard.Session.Status != "COMPLETE" {
		t.Fatalf("unexpected session status: %q", dashboard.Session.Status)
	}
	if len(dashboard.Phases) != 9 {
		t.Fatalf("expected nine phases, got %d", len(dashboard.Phases))
	}
	if len(dashboard.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(dashboard.Findings))
	}
	findingView := dashboard.Findings[0]
	if findingView.Kind != "COMPLIANCE GAP" || findingView.Severity != "HIGH" {
		t.Fatalf("unexpected finding mapping: %+v", findingView)
	}
	if findingView.Confidence != "HIGH" {
		t.Fatalf("unexpected confidence mapping: %q", findingView.Confidence)
	}
	if dashboard.Summary.Decision != "FAIL" {
		t.Fatalf("unexpected decision: %q", dashboard.Summary.Decision)
	}
}

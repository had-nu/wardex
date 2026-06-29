// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/report"
)

func TestReportGeneration(t *testing.T) {
	rep := model.GapReport{
		Summary: model.ExecutiveSummary{
			GeneratedAt:    time.Now(),
			GlobalCoverage: 45.0,
			TotalControls:  93,
			DomainSummaries: []model.DomainSummary{
				{Domain: "technological", TotalControls: 34},
			},
		},
		Gate: &model.GateReport{
			OverallDecision:   "block",
			GateMaturityLevel: 3,
			Decisions: []model.ReleaseDecision{
				{Decision: "block"},
			},
		},
		Roadmap: []model.Finding{
			{Control: model.CatalogControl{ID: "A.1"}},
		},
	}

	dir := t.TempDir()
	t.Chdir(dir)

	// Test JSON
	jsonFile := filepath.Join(dir, "report.json")
	if err := report.Generate(rep, "json", jsonFile, 10); err != nil {
		t.Fatalf("JSON generation failed: %v", err)
	}
	if _, err := os.Stat(jsonFile); os.IsNotExist(err) {
		t.Fatalf("JSON file not created")
	}

	// Test CSV
	csvFile := filepath.Join(dir, "report.csv")
	if err := report.Generate(rep, "csv", csvFile, 10); err != nil {
		t.Fatalf("CSV generation failed: %v", err)
	}
	if _, err := os.Stat(csvFile); os.IsNotExist(err) {
		t.Fatalf("CSV file not created")
	}

	// Test Markdown
	mdFile := filepath.Join(dir, "report.md")
	if err := report.Generate(rep, "markdown", mdFile, 10); err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}
	if _, err := os.Stat(mdFile); os.IsNotExist(err) {
		t.Fatalf("Markdown file not created")
	}

	// Test HTML
	htmlFile := filepath.Join(dir, "report.html")
	if err := report.Generate(rep, "html", htmlFile, 10); err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}
	if _, err := os.Stat(htmlFile); os.IsNotExist(err) {
		t.Fatalf("HTML file not created")
	}
}

func TestHTMLReportEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		coverage float64
		decision string
	}{
		{"high coverage", 85.0, "allow"},
		{"low coverage", 30.0, "block"},
		{"warning", 55.0, "warn"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := model.GapReport{
				Summary: model.ExecutiveSummary{
					GeneratedAt:    time.Now(),
					GlobalCoverage: tc.coverage,
					TotalControls:  93,
					CoveredCount:   int(tc.coverage * 93 / 100),
					DomainSummaries: []model.DomainSummary{
						{Domain: "technological", TotalControls: 34, CoveredCount: int(tc.coverage * 34 / 100)},
						{Domain: "organizational", TotalControls: 30, CoveredCount: int(tc.coverage * 30 / 100)},
					},
				},
				Gate: &model.GateReport{
					OverallDecision:   tc.decision,
					GateMaturityLevel: 3,
					Decisions: []model.ReleaseDecision{
						{Decision: tc.decision, Vulnerability: model.Vulnerability{CVEID: "CVE-2024-0001"}},
					},
				},
				Delta: &model.Delta{CoverageChange: 2.5},
				LayerDelta: &model.LayerDelta{
					DocumentedCount: 50, ImplementedCount: 30,
				},
				AssetCompliance: []model.AssetCompliance{
					{AssetName: "web-app", ComplianceScore: 0.9, Status: "compliant"},
					{AssetName: "db", ComplianceScore: 0.4, Status: "non_compliant", MissingControls: []string{"A.1"}},
				},
				Roadmap: []model.Finding{
					{Control: model.CatalogControl{ID: "A.5.1", Name: "Policy"}, FinalScore: 2.0, GapReasons: []string{"missing implementation"}},
				},
			}
			dir := t.TempDir()
			t.Chdir(dir)
			htmlFile := filepath.Join(dir, "report.html")
			if err := report.Generate(rep, "html", htmlFile, 10); err != nil {
				t.Fatalf("HTML generation failed: %v", err)
			}
			if _, err := os.Stat(htmlFile); os.IsNotExist(err) {
				t.Fatalf("HTML file not created")
			}
		})
	}
}

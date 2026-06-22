// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package sdk_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/sdk"
)

func TestAnalyze_WithValidControls(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "C1", Name: "Access Control", Maturity: 3, Domains: []string{"access_control"}},
		{ID: "C2", Name: "Cryptography", Maturity: 2, Domains: []string{"cryptography"}},
	}

	result, err := sdk.Analyze(controls, "iso27001")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Summary.TotalControls == 0 {
		t.Error("expected controls in summary")
	}
	// Verify structure is populated
	if len(result.Findings) == 0 {
		t.Error("expected findings in result")
	}
	if result.Posture.GlobalIndex == 0 && len(result.Findings) > 0 {
		// GlobalIndex can be 0 if no controls are covered; that's valid
	}
}

func TestAnalyze_WithEmptyControls(t *testing.T) {
	_, err := sdk.Analyze([]model.ExistingControl{}, "iso27001")
	if err == nil {
		t.Fatal("expected error for empty controls")
	}
	if !strings.Contains(err.Error(), "no controls provided") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAnalyze_WithNilControls(t *testing.T) {
	_, err := sdk.Analyze(nil, "iso27001")
	if err == nil {
		t.Fatal("expected error for nil controls")
	}
}

func TestAnalyze_AllFrameworks(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "C1", Name: "Access Control", Maturity: 3, Domains: []string{"access_control"}},
	}

	frameworks := []string{"iso27001", "dora", "nis2", "soc2"}
	for _, fw := range frameworks {
		t.Run(fw, func(t *testing.T) {
			result, err := sdk.Analyze(controls, fw)
			if err != nil {
				t.Fatalf("Analyze(%q) failed: %v", fw, err)
			}
			if result.Summary.TotalControls == 0 {
				t.Errorf("expected controls for framework %q", fw)
			}
		})
	}
}

func TestAnalyzeWithConfig_DefaultOptions(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "C1", Name: "Access Control", Maturity: 3, Domains: []string{"access_control"}},
	}

	result, err := sdk.AnalyzeWithConfig(controls, "iso27001", nil)
	if err != nil {
		t.Fatalf("AnalyzeWithConfig failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Summary.TotalControls == 0 {
		t.Error("expected controls in summary")
	}
}

func TestAnalyzeWithConfig_HighConfidenceFilter(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "C1", Name: "Access Control", Maturity: 5, Domains: []string{"access_control"}},
	}

	opts := &sdk.AnalyzeOptions{
		MinConfidence: "high",
	}

	result, err := sdk.AnalyzeWithConfig(controls, "iso27001", opts)
	if err != nil {
		t.Fatalf("AnalyzeWithConfig failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestAnalyzeWithConfig_FilterLowConfidence(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "C1", Name: "Access Control", Maturity: 4, Domains: []string{"access_control"}},
	}

	opts := &sdk.AnalyzeOptions{
		FilterLowConfidence: true,
	}

	result, err := sdk.AnalyzeWithConfig(controls, "iso27001", opts)
	if err != nil {
		t.Fatalf("AnalyzeWithConfig failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestLoadFramework_Iso27001(t *testing.T) {
	controls := sdk.LoadFramework("iso27001")
	if len(controls) == 0 {
		t.Fatal("expected ISO27001 controls")
	}

	// Should have multiple domains
	domains := make(map[string]bool)
	for _, c := range controls {
		domains[c.Domain] = true
	}
	if len(domains) < 3 {
		t.Errorf("expected multiple domains, got %d: %v", len(domains), domains)
	}
}

func TestLoadFramework_AllFrameworks(t *testing.T) {
	frameworks := []string{"iso27001", "dora", "nis2", "soc2"}
	for _, fw := range frameworks {
		t.Run(fw, func(t *testing.T) {
			controls := sdk.LoadFramework(fw)
			if len(controls) == 0 {
				t.Errorf("expected controls for framework %q", fw)
			}
		})
	}
}

func TestLoadControls_ValidFile(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `
controls:
  - id: C1
    name: Test Control
    maturity: 3
    domains: ["test"]
`
	yamlFile := filepath.Join(dir, "controls.yaml")
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	controls, err := sdk.LoadControls(yamlFile)
	if err != nil {
		t.Fatalf("LoadControls failed: %v", err)
	}
	if len(controls) == 0 {
		t.Error("expected at least one control")
	}
}

func TestLoadControls_InvalidPath(t *testing.T) {
	_, err := sdk.LoadControls("/nonexistent/path/controls.yaml")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}


func TestLoadControls_EmptyPaths(t *testing.T) {
	_, err := sdk.LoadControls()
	if err == nil {
		t.Fatal("expected error for empty paths")
	}
	if !strings.Contains(err.Error(), "no paths provided") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadControls_MultipleFiles(t *testing.T) {
	dir := t.TempDir()

	f1 := filepath.Join(dir, "c1.yaml")
	os.WriteFile(f1, []byte("controls:\n  - id: C1\n    name: Ctrl1\n    maturity: 3\n    domains: [\"a\"]\n"), 0644)

	f2 := filepath.Join(dir, "c2.yaml")
	os.WriteFile(f2, []byte("controls:\n  - id: C2\n    name: Ctrl2\n    maturity: 4\n    domains: [\"b\"]\n"), 0644)

	controls, err := sdk.LoadControls(f1, f2)
	if err != nil {
		t.Fatalf("LoadControls multi failed: %v", err)
	}
	if len(controls) != 2 {
		t.Errorf("expected 2 controls, got %d", len(controls))
	}
}

func TestLoadControls_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	jsonContent := `{"controls": [{"id": "C1", "name": "JSON Control", "maturity": 3, "domains": ["test"]}]}`
	jsonFile := filepath.Join(dir, "controls.json")
	if err := os.WriteFile(jsonFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	controls, err := sdk.LoadControls(jsonFile)
	if err != nil {
		t.Fatalf("LoadControls JSON failed: %v", err)
	}
	if len(controls) == 0 {
		t.Error("expected at least one control from JSON")
	}
}

func TestSnapshotDiff_WithResults(t *testing.T) {
	current := &sdk.AssessmentResult{
		Summary: model.ExecutiveSummary{
			TotalControls:  10,
			CoveredCount:   5,
			PartialCount:   3,
			GapCount:       2,
			GlobalCoverage: 50.0,
		},
	}
	previous := &sdk.AssessmentResult{
		Summary: model.ExecutiveSummary{
			TotalControls:  10,
			CoveredCount:   3,
			PartialCount:   4,
			GapCount:       3,
			GlobalCoverage: 30.0,
		},
	}

	delta := sdk.SnapshotDiff(current, previous)
	if delta.CoverageChange != 20.0 {
		t.Errorf("expected CoverageChange=20.0, got %f", delta.CoverageChange)
	}
}

func TestSnapshotSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	snapshotFile := filepath.Join(dir, "snapshot.json")

	result := &sdk.AssessmentResult{
		Summary: model.ExecutiveSummary{
			TotalControls:  5,
			CoveredCount:   3,
			GapCount:       2,
			GlobalCoverage: 60.0,
		},
	}

	err := sdk.SnapshotSave(snapshotFile, result)
	if err != nil {
		t.Fatalf("SnapshotSave failed: %v", err)
	}

	if _, err := os.Stat(snapshotFile); os.IsNotExist(err) {
		t.Fatal("snapshot file was not created")
	}

	loaded, err := sdk.SnapshotLoad(snapshotFile)
	if err != nil {
		t.Fatalf("SnapshotLoad failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil loaded snapshot")
	}
	if loaded.Summary.TotalControls != 5 {
		t.Errorf("expected TotalControls=5, got %d", loaded.Summary.TotalControls)
	}
	if loaded.Summary.GlobalCoverage != 60.0 {
		t.Errorf("expected GlobalCoverage=60.0, got %f", loaded.Summary.GlobalCoverage)
	}
}

func TestSnapshotLoad_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	missingPath := filepath.Join(dir, "nonexistent.json")
	result, err := sdk.SnapshotLoad(missingPath)
	if err != nil {
		t.Fatalf("SnapshotLoad should not error for missing file: %v", err)
	}
	if result != nil {
		t.Error("expected nil result for missing snapshot")
	}
}

func TestReport_WithValidResult(t *testing.T) {
	dir := t.TempDir()
	outputFile := filepath.Join(dir, "report.md")

	result := &sdk.AssessmentResult{
		Summary: model.ExecutiveSummary{
			TotalControls:  3,
			CoveredCount:   1,
			PartialCount:   1,
			GapCount:       1,
			GlobalCoverage: 33.3,
		},
	}

	err := sdk.Report(result, "markdown", outputFile, 10)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatal("report file was not created")
	}
}

func TestReport_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	outputFile := filepath.Join(dir, "report.json")

	result := &sdk.AssessmentResult{
		Summary: model.ExecutiveSummary{
			TotalControls:  1,
			CoveredCount:   1,
			GlobalCoverage: 100.0,
		},
	}

	err := sdk.Report(result, "json", outputFile, 10)
	if err != nil {
		t.Fatalf("Report JSON failed: %v", err)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatal("JSON report file was not created")
	}
}

func TestReport_CSVFormat(t *testing.T) {
	dir := t.TempDir()
	outputFile := filepath.Join(dir, "report.csv")

	result := &sdk.AssessmentResult{
		Summary: model.ExecutiveSummary{
			TotalControls:  1,
			CoveredCount:   0,
			GapCount:       1,
			GlobalCoverage: 0.0,
		},
	}

	err := sdk.Report(result, "csv", outputFile, 10)
	if err != nil {
		t.Fatalf("Report CSV failed: %v", err)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatal("CSV report file was not created")
	}
}

func TestAnalyze_RoadmapSortedByScore(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "A1", Name: "Access Control", Maturity: 1, Domains: []string{"access_control"}},
		{ID: "A2", Name: "Cryptography", Maturity: 2, Domains: []string{"cryptography"}},
		{ID: "A3", Name: "Physical Security", Maturity: 5, Domains: []string{"physical_security"}},
	}

	result, err := sdk.Analyze(controls, "iso27001")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Roadmap) > 1 {
		for i := 1; i < len(result.Roadmap); i++ {
			if result.Roadmap[i-1].FinalScore < result.Roadmap[i].FinalScore {
				t.Errorf("Roadmap not sorted descending at index %d: %f < %f",
					i, result.Roadmap[i-1].FinalScore, result.Roadmap[i].FinalScore)
			}
		}
	}
}

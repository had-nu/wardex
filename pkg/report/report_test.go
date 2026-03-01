package report_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/report"
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
}

package snapshot_test

import (
	"os"
	"testing"
	"time"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/snapshot"
)

func TestSnapshotSaveLoad(t *testing.T) {
	// Clean up before and after
	os.Remove(snapshot.SnapshotFile)
	defer os.Remove(snapshot.SnapshotFile)

	r, err := snapshot.Load()
	if err != nil {
		t.Fatalf("expected no error on missing file, got %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil on missing file, got %v", r)
	}

	report := model.GapReport{
		Summary: model.ExecutiveSummary{
			GlobalCoverage: 45.0,
			GeneratedAt:    time.Now().Truncate(time.Second),
		},
	}

	if err := snapshot.Save(report); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	r, err = snapshot.Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if r.Summary.GlobalCoverage != 45.0 {
		t.Errorf("expected global coverage 45.0, got %f", r.Summary.GlobalCoverage)
	}
}

func TestSnapshotDiff(t *testing.T) {
	prev := model.GapReport{
		Summary: model.ExecutiveSummary{GlobalCoverage: 40.0, GeneratedAt: time.Now()},
		Findings: []model.Finding{
			{Control: model.AnnexAControl{ID: "A.1"}, Status: model.StatusGap},
			{Control: model.AnnexAControl{ID: "A.2"}, Status: model.StatusCovered},
			{Control: model.AnnexAControl{ID: "A.3"}, Status: model.StatusGap},
		},
		Gate: &model.GateReport{GateMaturityLevel: 2},
	}

	curr := model.GapReport{
		Summary: model.ExecutiveSummary{GlobalCoverage: 50.0},
		Findings: []model.Finding{
			{Control: model.AnnexAControl{ID: "A.1"}, Status: model.StatusCovered}, // fixed
			{Control: model.AnnexAControl{ID: "A.2"}, Status: model.StatusGap},     // regressed
			{Control: model.AnnexAControl{ID: "A.3"}, Status: model.StatusGap},     // unchanged
		},
		Gate: &model.GateReport{GateMaturityLevel: 4}, // improved
	}

	delta := snapshot.Diff(curr, prev)

	if delta.CoverageChange != 10.0 {
		t.Errorf("expected coverage change 10.0, got %f", delta.CoverageChange)
	}
	if delta.GateMaturityChange != 2 {
		t.Errorf("expected gate maturity change 2, got %d", delta.GateMaturityChange)
	}
	if len(delta.NewlyCovered) != 1 || delta.NewlyCovered[0] != "A.1" {
		t.Errorf("expected A.1 as newly covered")
	}
	if len(delta.NewGaps) != 1 || delta.NewGaps[0] != "A.2" {
		t.Errorf("expected A.2 as new gap")
	}
	if delta.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", delta.Unchanged)
	}
}

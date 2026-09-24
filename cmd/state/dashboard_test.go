package state

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/statestore"
	"github.com/spf13/cobra"
)

func TestStateHistoryUsesConfiguredOutputWriter(t *testing.T) {
	oldDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = oldDir }()

	var out, errOut bytes.Buffer
	cmd := &cobra.Command{Use: "history"}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := HistoryCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("history returned error: %v", err)
	}
	if !strings.Contains(out.String(), "No history records found") {
		t.Fatalf("expected history result on configured stdout, got %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", errOut.String())
	}
}

func TestBuildStateStatusDashboard(t *testing.T) {
	state := &statestore.State{
		Version:      statestore.StateVersion,
		LastRun:      time.Now().UTC(),
		LastDecision: model.DecisionWarn,
		LastRisk:     0.42,
		RunCount:     3,
	}
	dashboard := buildStateStatusDashboard(".wardex", state, errors.New("broken chain"))
	if dashboard.Summary.Decision != "BROKEN" || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected state status dashboard: %+v", dashboard)
	}
}

func TestBuildStateTrendDashboard(t *testing.T) {
	analysis := &statestore.TrendAnalysis{
		Direction:  statestore.TrendWorsening,
		TotalRuns:  1,
		AllowCount: 0,
		WarnCount:  0,
		BlockCount: 1,
	}
	history := []statestore.TrendPoint{{Date: time.Now().UTC(), Risk: 0.8, Decision: model.DecisionBlock, VulnCount: 2}}
	dashboard := buildStateTrendDashboard(".wardex", analysis, history)
	if dashboard.Summary.Decision != "WORSENING" || len(dashboard.Findings) != 1 {
		t.Fatalf("unexpected state trend dashboard: %+v", dashboard)
	}
}

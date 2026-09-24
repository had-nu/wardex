package gatecmd

import (
	"testing"
	"time"
)

func TestBuildGateCheckDashboardDuplicate(t *testing.T) {
	dashboard := buildGateCheckDashboard(
		"gate.log",
		"1.2.3",
		"DUPLICATE",
		"iso27001:A.8.1",
		time.Unix(0, 0).UTC(),
		"entry-hash",
		false,
	)
	if dashboard.Summary.Decision != "DUPLICATE" || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected gate dashboard: %+v", dashboard)
	}
}

func TestBuildGateErrorDashboard(t *testing.T) {
	dashboard := buildGateErrorDashboard("gate.log", "1.2.3", "missing log")
	if dashboard.Summary.Decision != "ERROR" || len(dashboard.Findings) != 1 {
		t.Fatalf("unexpected gate error dashboard: %+v", dashboard)
	}
}

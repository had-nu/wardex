package contract

import (
	"testing"
	"time"
)

func TestBuildContractDashboard(t *testing.T) {
	dashboard := buildContractDashboard(
		"contract.pdf",
		"sha256:abc",
		42,
		time.Unix(0, 0).UTC(),
		"sha256:abc",
		"VERIFIED",
	)
	if dashboard.Summary.Decision != "VERIFIED" || len(dashboard.Findings) != 1 {
		t.Fatalf("unexpected contract dashboard: %+v", dashboard)
	}
}

func TestBuildContractDashboardMismatch(t *testing.T) {
	dashboard := buildContractDashboard("contract.pdf", "sha256:abc", 42, time.Time{}, "sha256:def", "MISMATCH")
	if dashboard.Summary.Decision != "MISMATCH" || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected mismatch dashboard: %+v", dashboard)
	}
}

package auth

import (
	"bytes"
	"errors"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

func TestAuthColorDoesNotDecorateNonTerminalOutput(t *testing.T) {
	var out bytes.Buffer
	if got := authColor(&out, "VALID", ui.Green); got != "VALID" {
		t.Fatalf("unexpected non-terminal color value: %q", got)
	}
}

func TestBuildAuthStatusDashboard(t *testing.T) {
	dashboard := buildAuthStatusDashboard("trust.yaml", 2, 1, "admin-01", errors.New("bad signature"))
	if dashboard.Summary.Decision != "INVALID" {
		t.Fatalf("expected INVALID decision, got %q", dashboard.Summary.Decision)
	}
	if len(dashboard.Findings) != 1 || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected status finding: %+v", dashboard.Findings)
	}
}

func TestBuildAuthVerifyDashboardRevoked(t *testing.T) {
	entry := trust.KeyEntry{ID: "key-01", Actor: "analyst@example.test", Name: "Analyst", Role: trust.RoleAnalyst}
	dashboard := buildAuthVerifyDashboard("trust.yaml", entry, true)
	if dashboard.Summary.Decision != "REVOKED" || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected revoked dashboard: %+v", dashboard)
	}
}

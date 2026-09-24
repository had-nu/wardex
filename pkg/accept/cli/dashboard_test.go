package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/spf13/cobra"
)

func TestBuildAcceptListDashboardDoesNotExposePayloads(t *testing.T) {
	dashboard := buildAcceptListDashboard([]model.Acceptance{{
		ID:            "acc-1",
		CVE:           "CVE-2026-0001",
		AcceptedBy:    "owner@example.test",
		Justification: "do not expose this justification",
		Signature:     "do-not-expose-signature",
		ExpiresAt:     time.Now().Add(-time.Hour),
	}}, "all")
	if dashboard.Summary.Decision != "LOADED" || len(dashboard.Findings) != 1 {
		t.Fatalf("unexpected acceptance dashboard: %+v", dashboard)
	}
	var builder strings.Builder
	for _, field := range dashboard.Findings[0].Fields {
		builder.WriteString(field.Label)
		builder.WriteString(field.Value)
	}
	if strings.Contains(builder.String(), "do not expose") || strings.Contains(builder.String(), "do-not-expose") {
		t.Fatalf("sensitive acceptance values leaked into dashboard: %s", builder.String())
	}
}

func TestAcceptWritersFollowCobraConfiguration(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := &cobra.Command{Use: "accept"}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if got := acceptCommandOutput(cmd); got != &out {
		t.Fatalf("configured stdout writer was not selected")
	}

	oldStderr := stderr
	stderr = os.Stderr
	defer func() { stderr = oldStderr }()
	if got := acceptErrorWriter(cmd); got != &errOut {
		t.Fatalf("configured stderr writer was not selected")
	}
}

func TestSafeBackendLabelRemovesCredentialsAndQuery(t *testing.T) {
	raw := "https://user:password@example.test/hook?token=secret"
	got := safeBackendLabel(raw)
	if got != "https://example.test" {
		t.Fatalf("unexpected sanitized backend: %q", got)
	}
	message := safeBackendError(fmt.Errorf("request failed for %s", raw), raw)
	if strings.Contains(message, "password") || strings.Contains(message, "secret") {
		t.Fatalf("backend credentials leaked in error: %s", message)
	}
}

func TestSafeBackendLabelFailsClosed(t *testing.T) {
	malformed := "https://user:password@%zz"
	if got := safeBackendLabel(malformed); strings.Contains(got, "password") || got == malformed {
		t.Fatalf("malformed backend was not sanitized: %q", got)
	}
	if got := safeBackendLabel("user:password@example.test:443"); strings.Contains(got, "password") {
		t.Fatalf("bare backend credentials were not sanitized: %q", got)
	}
	if got := safeBackendError(fmt.Errorf("redirected to https://other.test/token"), "https://example.test"); got != "request failed" {
		t.Fatalf("unexpected URL error sanitization: %q", got)
	}
}

func TestBuildAcceptForwardingDashboardDoesNotExposeBackend(t *testing.T) {
	dashboard := buildAcceptForwardingDashboard("audit.log", 12, 2, "all", true)
	if dashboard.Summary.Decision != "FORWARDING READY" {
		t.Fatalf("unexpected forwarding decision: %q", dashboard.Summary.Decision)
	}
	if dashboard.Summary.Fields[4].Value != "configured" {
		t.Fatalf("expected sanitized backend label, got %q", dashboard.Summary.Fields[4].Value)
	}
}

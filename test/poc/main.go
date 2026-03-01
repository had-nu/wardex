// sdk-poc/main.go
//
// Wardex SDK Integration PoC
// Exercises all four validation scenarios directly via the pkg/ API,
// without the CLI. Useful for unit testing the library in isolation
// or embedding wardex in a larger Go service.
//
// Run: go run ./sdk-poc/
// Expected output: 4 scenario results printed; exit 0 if all pass.

package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	scenarios := []struct {
		name      string
		gate      releasegate.Gate
		vulns     []model.Vulnerability
		wantAllow bool
	}{
		// ── Scenario 01: Happy Path ─────────────────────────────────────────
		// Low CVSS, low EPSS, not reachable, low-criticality internal service.
		// Composite risk << 6.0 → ALLOW expected.
		{
			name: "01 · Happy Path → ALLOW",
			gate: releasegate.Gate{
				AssetContext: model.AssetContext{
					Criticality:    0.3,
					InternetFacing: false,
					RequiresAuth:   true,
				},
				CompensatingControls: nil,
				RiskAppetite:         6.0,
			},
			vulns: []model.Vulnerability{
				{CVEID: "CVE-2024-9901", CVSSBase: 3.2, EPSSScore: 0.018, Reachable: false},
				{CVEID: "CVE-2024-7743", CVSSBase: 2.8, EPSSScore: 0.005, Reachable: false},
			},
			wantAllow: true,
		},

		// ── Scenario 02: Block Path ─────────────────────────────────────────
		// Critical RCE, high EPSS, reachable from internet, no controls.
		// Composite risk >> 6.0 → BLOCK expected.
		{
			name: "02 · Critical CVE → BLOCK",
			gate: releasegate.Gate{
				AssetContext: model.AssetContext{
					Criticality:    0.95,
					InternetFacing: true,
					RequiresAuth:   false,
				},
				CompensatingControls: nil,
				RiskAppetite:         6.0,
			},
			vulns: []model.Vulnerability{
				{CVEID: "CVE-2024-1234", CVSSBase: 9.8, EPSSScore: 0.91, Reachable: true},
				{CVEID: "CVE-2024-5566", CVSSBase: 8.6, EPSSScore: 0.73, Reachable: true},
			},
			wantAllow: false,
		},

		// ── Scenario 03: Compensating Controls ─────────────────────────────
		// High CVSS would block, but WAF + auth + segmentation dampen the
		// composite score below the 6.0 appetite threshold → ALLOW expected.
		{
			name: "03 · Compensating Controls → ALLOW",
			gate: releasegate.Gate{
				AssetContext: model.AssetContext{
					Criticality:    0.75,
					InternetFacing: true,
					RequiresAuth:   true,
				},
				CompensatingControls: []model.CompensatingControl{
					{Type: "waf", Effectiveness: 0.40},
					{Type: "auth", Effectiveness: 0.30},
					{Type: "network_segmentation", Effectiveness: 0.15},
				},
				RiskAppetite: 6.0,
			},
			vulns: []model.Vulnerability{
				{CVEID: "CVE-2024-3388", CVSSBase: 8.1, EPSSScore: 0.45, Reachable: true},
				{CVEID: "CVE-2024-6610", CVSSBase: 7.4, EPSSScore: 0.31, Reachable: true},
			},
			wantAllow: true,
		},

		// ── Scenario 04: Risk Acceptance ────────────────────────────────────
		// Without an active acceptance record this would BLOCK (CVE-2025-0042,
		// CVSS 9.1). The CLI scenario registers an exception; here we validate
		// the raw gate behaviour (pre-acceptance) returns BLOCK as expected,
		// which is the correct baseline for the acceptance flow to act on.
		{
			name: "04 · Risk Acceptance baseline → BLOCK (pre-exception)",
			gate: releasegate.Gate{
				AssetContext: model.AssetContext{
					Criticality:    0.85,
					InternetFacing: true,
					RequiresAuth:   false,
				},
				CompensatingControls: nil,
				RiskAppetite:         6.0,
			},
			vulns: []model.Vulnerability{
				{CVEID: "CVE-2025-0042", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true},
			},
			wantAllow: false,
		},
	}

	passed := 0
	failed := 0

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║     Wardex SDK PoC — Scenario Validation         ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()

	for _, s := range scenarios {
		report := s.gate.Evaluate(s.vulns)
		gotAllow := report.OverallDecision == "allow"

		var status, icon string
		if gotAllow == s.wantAllow {
			status = "PASS"
			icon = "✅"
			passed++
		} else {
			status = "FAIL"
			icon = "❌"
			failed++
		}

		fmt.Printf("%s [%s] %s\n", icon, status, s.name)
		fmt.Printf("      Gate decision : %s\n", report.OverallDecision)

		// Log individual vulnerability scores for traceability.
		for _, vr := range report.Decisions {
			logger.Info("vuln evaluated",
				"cve", vr.Vulnerability.CVEID,
				"composite", fmt.Sprintf("%.2f", vr.ReleaseRisk),
				"decision", vr.Decision,
			)
		}
		fmt.Println()
	}

	fmt.Printf("─────────────────────────────────────────────────────\n")
	fmt.Printf("Results: %d passed / %d failed\n", passed, failed)

	if failed > 0 {
		fmt.Println("❌ PoC validation FAILED — review scenario output above.")
		os.Exit(1)
	}
	fmt.Println("✅ All scenarios passed — wardex library behaves as expected.")
}

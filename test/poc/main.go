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
			icon = "[PASS]"
			passed++
		} else {
			status = "FAIL"
			icon = "[FAIL]"
			failed++
		}

		fmt.Printf("%s [%s] %s\n", icon, status, s.name)
		fmt.Printf("      Gate decision : %s\n", report.OverallDecision)

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
		fmt.Println("[FAIL] PoC validation FAILED — review scenario output above.")
		os.Exit(1)
	}
	fmt.Println("[PASS] All scenarios passed — wardex library behaves as expected.")
}

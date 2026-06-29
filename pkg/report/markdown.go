// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
)

func generateMarkdown(report model.GapReport, outFile string, limit int) error { // nolint:errcheck
	var f *os.File

	if outFile == "stdout" || outFile == "" {
		f = os.Stdout
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		safePathStr, err := cli.ValidateOutputPath(cwd, outFile)
		if err != nil {
			return err
		}
		f, err = os.Create(safePathStr) // #nosec G304
		if err != nil {
			return fmt.Errorf("failed to create Markdown file: %w", err)
		}
		defer func() { _ = f.Close() }()
	}

	// Simplify Markdown generation manually since lipgloss is for terminal ANSI colors

	_, _ = fmt.Fprintf(f, "# ISO 27001:2022 — Compliance & Release Gate Report\n")                    // nolint:errcheck
	_, _ = fmt.Fprintf(f, "**Generated:** %s\n\n", report.Summary.GeneratedAt.Format("2006-01-02 15:04:05")) // nolint:errcheck
	_, _ = fmt.Fprintf(f, "---\n\n## Executive Summary\n\n")                                                  // nolint:errcheck

	_, _ = fmt.Fprintf(f, "| Metric | Value |\n|---|---|\n")
	_, _ = fmt.Fprintf(f, "| Global Compliance Coverage | %.1f%% |\n", report.Summary.GlobalCoverage)
	_, _ = fmt.Fprintf(f, "| Controls Covered | %d / %d |\n", report.Summary.CoveredCount, report.Summary.TotalControls)
	_, _ = fmt.Fprintf(f, "| Controls Partial | %d / %d |\n", report.Summary.PartialCount, report.Summary.TotalControls)
	_, _ = fmt.Fprintf(f, "| Controls Gap | %d / %d |\n", report.Summary.GapCount, report.Summary.TotalControls)

	if report.Delta != nil {
		sign := ""
		if report.Delta.CoverageChange > 0 {
			sign = "+"
		}
		_, _ = fmt.Fprintf(f, "| Coverage vs Last Run | %s%.1f%% |\n", sign, report.Delta.CoverageChange)
	}

	if report.Gate != nil {
		icon := "[OK] ALLOW"
		switch report.Gate.OverallDecision {
		case "block":
			icon = "[X] BLOCK"
		case "warn":
			icon = "[!] WARN"
		}
		_, _ = fmt.Fprintf(f, "| Release Gate Decision | %s |\n", icon)
		_, _ = fmt.Fprintf(f, "| Gate Maturity Level | %d / 5 |\n", report.Gate.GateMaturityLevel)
	}

	_, _ = fmt.Fprintf(f, "\n---\n\n## Coverage by Domain\n\n")
	_, _ = fmt.Fprintf(f, "| Domain | Covered | Partial | Gap | Maturity Avg |\n|---|---|---|---|---|\n")
	for _, d := range report.Summary.DomainSummaries {
		_, _ = fmt.Fprintf(f, "| %s | %d/%d | %d | %d | %.1f |\n",
			d.Domain, d.CoveredCount, d.TotalControls, d.PartialCount, d.GapCount, d.MaturityScore)
	}

	if report.LayerDelta != nil {
		_, _ = fmt.Fprintf(f, "\n---\n\n## Layer Delta\n\n")
		_, _ = fmt.Fprintf(f, "| Metric | Value |\n|---|---|\n")
		_, _ = fmt.Fprintf(f, "| Documented Controls | %d |\n", report.LayerDelta.DocumentedCount)
		_, _ = fmt.Fprintf(f, "| Implemented Controls | %d |\n", report.LayerDelta.ImplementedCount)
		_, _ = fmt.Fprintf(f, "| Active Coverage (Paper ∩ Code) | %d |\n", len(report.LayerDelta.ActiveCoverage))
		_, _ = fmt.Fprintf(f, "| Policy Gap (Paper Security) | %d |\n", len(report.LayerDelta.PolicyGap))
		_, _ = fmt.Fprintf(f, "| Shadow Security (Implemented only) | %d |\n", len(report.LayerDelta.ImplementedOnly))

		if len(report.LayerDelta.PolicyGap) > 0 {
			_, _ = fmt.Fprintf(f, "\n**Top Policy Gaps (Paper only):** %v\n", report.LayerDelta.PolicyGap)
		}
	}

	if len(report.AssetCompliance) > 0 {
		_, _ = fmt.Fprintf(f, "\n---\n\n## Asset Compliance\n\n")
		_, _ = fmt.Fprintf(f, "| Asset | Score | Status | Missing |\n|---|---|---|---|\n")
		for _, ac := range report.AssetCompliance {
			missingStr := "none"
			if len(ac.MissingControls) > 0 {
				missingStr = fmt.Sprintf("%d controls", len(ac.MissingControls))
			}
			_, _ = fmt.Fprintf(f, "| %s | %.1f%% | %s | %s |\n",
				ac.AssetName, ac.ComplianceScore*100.0, ac.Status, missingStr)
		}
	}

	if report.Gate != nil {
		_, _ = fmt.Fprintf(f, "\n---\n\n## Release Gate — Decision Breakdown\n\n")
		_, _ = fmt.Fprintf(f, "| CVE | CVSS | EPSS | Release Risk | Decision |\n|---|---|---|---|---|\n")
		for _, dec := range report.Gate.Decisions {
			icon := "[OK] ALLOW"
			switch dec.Decision {
			case "block":
				icon = "[X] BLOCK"
			case "warn":
				icon = "[!] WARN"
			}
			_, _ = fmt.Fprintf(f, "| %s | %.1f | %.2f | **%.1f** | %s |\n",
				dec.Vulnerability.CVEID, dec.Breakdown.CVSSBase, dec.Breakdown.EPSSFactor, dec.ReleaseRisk, icon)
		}
		_, _ = fmt.Fprintf(f, "\n**Gate Maturity:** Level %d\n", report.Gate.GateMaturityLevel)
	}

	_, _ = fmt.Fprintf(f, "\n---\n\n## Roadmap (prioritized)\n\n")
	_, _ = fmt.Fprintf(f, "| Control | Name | Score | Reason |\n|---|---|---|---|\n")

	count := 0
	for _, fnd := range report.Roadmap {
		if limit > 0 && count >= limit {
			break
		}
		reason := "N/A"
		if len(fnd.GapReasons) > 0 {
			reason = fnd.GapReasons[0]
		}
		_, _ = fmt.Fprintf(f, "| %s | %s | %.1f | %s |\n", fnd.Control.ID, fnd.Control.Name, fnd.FinalScore, reason)
		count++
	}

	return nil
}

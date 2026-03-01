package report

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

func generateMarkdown(report model.GapReport, outFile string, limit int) error {
	var f *os.File
	var err error

	if outFile == "stdout" || outFile == "" {
		f = os.Stdout
	} else {
		f, err = os.Create(outFile)
		if err != nil {
			return fmt.Errorf("failed to create Markdown file: %w", err)
		}
		defer f.Close()
	}

	// Simplify Markdown generation manually since lipgloss is for terminal ANSI colors

	fmt.Fprintf(f, "# ISO 27001:2022 — Compliance & Release Gate Report\n")
	fmt.Fprintf(f, "**Generated:** %s\n\n", report.Summary.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "---\n\n## Executive Summary\n\n")

	fmt.Fprintf(f, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(f, "| Global Compliance Coverage | %.1f%% |\n", report.Summary.GlobalCoverage)
	fmt.Fprintf(f, "| Controls Covered | %d / %d |\n", report.Summary.CoveredCount, report.Summary.TotalControls)
	fmt.Fprintf(f, "| Controls Partial | %d / %d |\n", report.Summary.PartialCount, report.Summary.TotalControls)
	fmt.Fprintf(f, "| Controls Gap | %d / %d |\n", report.Summary.GapCount, report.Summary.TotalControls)

	if report.Delta != nil {
		sign := ""
		if report.Delta.CoverageChange > 0 {
			sign = "+"
		}
		fmt.Fprintf(f, "| Coverage vs Last Run | %s%.1f%% |\n", sign, report.Delta.CoverageChange)
	}

	if report.Gate != nil {
		icon := "[OK] ALLOW"
		if report.Gate.OverallDecision == "block" {
			icon = "[X] BLOCK"
		} else if report.Gate.OverallDecision == "warn" {
			icon = "[!] WARN"
		}
		fmt.Fprintf(f, "| Release Gate Decision | %s |\n", icon)
		fmt.Fprintf(f, "| Gate Maturity Level | %d / 5 |\n", report.Gate.GateMaturityLevel)
	}

	fmt.Fprintf(f, "\n---\n\n## Coverage by Domain\n\n")
	fmt.Fprintf(f, "| Domain | Covered | Partial | Gap | Maturity Avg |\n|---|---|---|---|---|\n")
	for _, d := range report.Summary.DomainSummaries {
		fmt.Fprintf(f, "| %s | %d/%d | %d | %d | %.1f |\n",
			d.Domain, d.CoveredCount, d.TotalControls, d.PartialCount, d.GapCount, d.MaturityScore)
	}

	if report.Gate != nil {
		fmt.Fprintf(f, "\n---\n\n## Release Gate — Decision Breakdown\n\n")
		fmt.Fprintf(f, "| CVE | CVSS | EPSS | Release Risk | Decision |\n|---|---|---|---|---|\n")
		for _, dec := range report.Gate.Decisions {
			icon := "[OK] ALLOW"
			if dec.Decision == "block" {
				icon = "[X] BLOCK"
			} else if dec.Decision == "warn" {
				icon = "[!] WARN"
			}
			fmt.Fprintf(f, "| %s | %.1f | %.2f | **%.1f** | %s |\n",
				dec.Vulnerability.CVEID, dec.Breakdown.CVSSBase, dec.Breakdown.EPSSFactor, dec.ReleaseRisk, icon)
		}
		fmt.Fprintf(f, "\n**Gate Maturity:** Level %d\n", report.Gate.GateMaturityLevel)
	}

	fmt.Fprintf(f, "\n---\n\n## Roadmap (prioritized)\n\n")
	fmt.Fprintf(f, "| Control | Name | Score | Reason |\n|---|---|---|---|\n")

	count := 0
	for _, fnd := range report.Roadmap {
		if limit > 0 && count >= limit {
			break
		}
		reason := "N/A"
		if len(fnd.GapReasons) > 0 {
			reason = fnd.GapReasons[0]
		}
		fmt.Fprintf(f, "| %s | %s | %.1f | %s |\n", fnd.Control.ID, fnd.Control.Name, fnd.FinalScore, reason)
		count++
	}

	return nil
}

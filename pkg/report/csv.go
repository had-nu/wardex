// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
)

func generateCSV(report model.GapReport, outFile string) error {
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
			return fmt.Errorf("failed to create CSV file: %w", err)
		}
		defer func() { _ = f.Close() }()
	}

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{"Control ID", "Name", "Domain", "Status", "Score", "Maturity", "Gap Reasons"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, finding := range report.Findings {
		reasons := ""
		if len(finding.GapReasons) > 0 {
			reasons = finding.GapReasons[0]
		}

		row := []string{
			finding.Control.ID,
			finding.Control.Name,
			finding.Control.Domain,
			string(finding.Status),
			fmt.Sprintf("%.2f", finding.FinalScore),
			fmt.Sprintf("%.1f", finding.EffectiveMaturity),
			reasons,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()

	if report.Gate != nil || report.Delta != nil {
		if err := writer.Write([]string{}); err != nil {
			return fmt.Errorf("failed to write CSV separator: %w", err)
		}

		if err := writer.Write([]string{"## Release Gate"}); err != nil {
			return fmt.Errorf("failed to write section header: %w", err)
		}

		gateHeader := []string{"CVE", "CVSS", "EPSS", "Release Risk", "Decision"}
		if err := writer.Write(gateHeader); err != nil {
			return fmt.Errorf("failed to write gate header: %w", err)
		}

		if report.Gate != nil {
			for _, dec := range report.Gate.Decisions {
				row := []string{
					dec.Vulnerability.CVEID,
					fmt.Sprintf("%.1f", dec.Breakdown.CVSSBase),
					fmt.Sprintf("%.2f", dec.Breakdown.EPSSFactor),
					fmt.Sprintf("%.1f", dec.ReleaseRisk),
					dec.Decision,
				}
				if err := writer.Write(row); err != nil {
					return fmt.Errorf("failed to write gate row: %w", err)
				}
			}

			if err := writer.Write([]string{}); err != nil {
				return fmt.Errorf("failed to write CSV separator: %w", err)
			}

			summaryRow := []string{
				fmt.Sprintf("Overall Decision: %s", report.Gate.OverallDecision),
				fmt.Sprintf("Gate Maturity Level: %d", report.Gate.GateMaturityLevel),
				"", "", "",
			}
			if err := writer.Write(summaryRow); err != nil {
				return fmt.Errorf("failed to write gate summary: %w", err)
			}
		}
	}

	if report.Delta != nil {
		if err := writer.Write([]string{}); err != nil {
			return fmt.Errorf("failed to write CSV separator: %w", err)
		}

		if err := writer.Write([]string{"## Snapshot Delta"}); err != nil {
			return fmt.Errorf("failed to write delta header: %w", err)
		}

		deltaHeader := []string{"Coverage Change", "Newly Covered", "New Gaps", "Unchanged"}
		if err := writer.Write(deltaHeader); err != nil {
			return fmt.Errorf("failed to write delta header: %w", err)
		}

		deltaRow := []string{
			fmt.Sprintf("%.1f%%", report.Delta.CoverageChange),
			fmt.Sprintf("%d", len(report.Delta.NewlyCovered)),
			fmt.Sprintf("%d", len(report.Delta.NewGaps)),
			fmt.Sprintf("%d", report.Delta.Unchanged),
		}
		if err := writer.Write(deltaRow); err != nil {
			return fmt.Errorf("failed to write delta row: %w", err)
		}
	}

	if report.LayerDelta != nil {
		if err := writer.Write([]string{}); err != nil {
			return fmt.Errorf("failed to write CSV separator: %w", err)
		}
		if err := writer.Write([]string{"## Layer Delta"}); err != nil {
			return fmt.Errorf("failed to write section header: %w", err)
		}
		_ = writer.Write([]string{"Metric", "Value"})
		_ = writer.Write([]string{"Documented Count", fmt.Sprintf("%d", report.LayerDelta.DocumentedCount)})
		_ = writer.Write([]string{"Implemented Count", fmt.Sprintf("%d", report.LayerDelta.ImplementedCount)})
		_ = writer.Write([]string{"Active Coverage", fmt.Sprintf("%d", len(report.LayerDelta.ActiveCoverage))})
		_ = writer.Write([]string{"Policy Gap", fmt.Sprintf("%d", len(report.LayerDelta.PolicyGap))})
		_ = writer.Write([]string{"Shadow Security", fmt.Sprintf("%d", len(report.LayerDelta.ImplementedOnly))})
	}

	if len(report.AssetCompliance) > 0 {
		if err := writer.Write([]string{}); err != nil {
			return fmt.Errorf("failed to write CSV separator: %w", err)
		}
		if err := writer.Write([]string{"## Asset Compliance"}); err != nil {
			return fmt.Errorf("failed to write section header: %w", err)
		}
		_ = writer.Write([]string{"Asset ID", "Asset Name", "Score", "Status", "Missing Count"})
		for _, ac := range report.AssetCompliance {
			_ = writer.Write([]string{
				ac.AssetID,
				ac.AssetName,
				fmt.Sprintf("%.1f%%", ac.ComplianceScore*100.0),
				ac.Status,
				fmt.Sprintf("%d", len(ac.MissingControls)),
			})
		}
	}

	writer.Flush()
	return nil
}

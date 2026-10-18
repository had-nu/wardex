// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
)

func generateCSV(report model.GapReport, outFile string, writers ...io.Writer) error {
	stdout := selectReportStdout(writers)
	f := io.Writer(stdout)

	if outFile != "stdout" && outFile != "" {
		safePathStr, err := cli.SafeOutputPath(outFile)
		if err != nil {
			return err
		}
		file, err := os.Create(safePathStr) // #nosec G304
		if err != nil {
			return fmt.Errorf("failed to create CSV file: %w", err)
		}
		f = file
		defer func() { _ = file.Close() }()
	}

	writer := csv.NewWriter(f)

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
					string(dec.Decision),
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
		if err := writer.Write([]string{"Metric", "Value"}); err != nil {
			return fmt.Errorf("failed to write layer metric header: %w", err)
		}
		layerRows := [][]string{
			{"Documented Count", fmt.Sprintf("%d", report.LayerDelta.DocumentedCount)},
			{"Implemented Count", fmt.Sprintf("%d", report.LayerDelta.ImplementedCount)},
			{"Active Coverage", fmt.Sprintf("%d", len(report.LayerDelta.ActiveCoverage))},
			{"Policy Gap", fmt.Sprintf("%d", len(report.LayerDelta.PolicyGap))},
			{"Shadow Security", fmt.Sprintf("%d", len(report.LayerDelta.ImplementedOnly))},
		}
		for _, row := range layerRows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write layer metric: %w", err)
			}
		}
	}

	if len(report.AssetCompliance) > 0 {
		if err := writer.Write([]string{}); err != nil {
			return fmt.Errorf("failed to write CSV separator: %w", err)
		}
		if err := writer.Write([]string{"## Asset Compliance"}); err != nil {
			return fmt.Errorf("failed to write section header: %w", err)
		}
		if err := writer.Write([]string{"Asset ID", "Asset Name", "Score", "Status", "Missing Count"}); err != nil {
			return fmt.Errorf("failed to write asset header: %w", err)
		}
		for _, ac := range report.AssetCompliance {
			if err := writer.Write([]string{
				ac.AssetID,
				ac.AssetName,
				fmt.Sprintf("%.1f%%", ac.ComplianceScore*100.0),
				ac.Status,
				fmt.Sprintf("%d", len(ac.MissingControls)),
			}); err != nil {
				return fmt.Errorf("failed to write asset row: %w", err)
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to flush CSV output: %w", err)
	}
	return nil
}

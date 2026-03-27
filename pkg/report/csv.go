// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/utils"
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
		safePathStr, err := utils.SafePath(cwd, outFile)
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

	header := []string{"Control ID", "Name", "Domain", "Status", "Score", "Gap Reasons"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, finding := range report.Findings {
		reasons := ""
		if len(finding.GapReasons) > 0 {
			reasons = finding.GapReasons[0] // Simplify for CSV
		}

		row := []string{
			finding.Control.ID,
			finding.Control.Name,
			finding.Control.Domain,
			string(finding.Status),
			fmt.Sprintf("%.2f", finding.FinalScore),
			reasons,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

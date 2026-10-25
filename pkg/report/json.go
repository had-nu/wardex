// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v3/pkg/model"
)

func generateJSON(report model.GapReport, outFile string, writers ...io.Writer) error {
	stdout := selectReportStdout(writers)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	if outFile == "stdout" || outFile == "" {
		if _, err := fmt.Fprintln(stdout, string(data)); err != nil {
			return err
		}
		return nil
	}

	return os.WriteFile(outFile, data, 0600)
}

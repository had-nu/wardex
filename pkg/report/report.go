// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"fmt"
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

// Generate delegates reporting based on the requested format.
func Generate(report model.GapReport, format string, outFile string, limit int) error {
	format = strings.ToLower(format)

	switch format {
	case "markdown":
		return generateMarkdown(report, outFile, limit)
	case "json":
		return generateJSON(report, outFile)
	case "csv":
		return generateCSV(report, outFile)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

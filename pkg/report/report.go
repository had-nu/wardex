// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/model"
)

func selectReportStdout(writers []io.Writer) io.Writer {
	if len(writers) > 0 && writers[0] != nil {
		return writers[0]
	}
	return os.Stdout
}

// supportedFormats is the single source of truth for report output formats.
// Flag help, validation and docs derive from it so they cannot disagree.
var supportedFormats = []string{"markdown", "json", "csv", "html"}

// SupportedFormats returns the accepted report formats in stable order.
func SupportedFormats() []string {
	out := make([]string, len(supportedFormats))
	copy(out, supportedFormats)
	return out
}

// IsSupportedFormat reports whether this build can emit the given format.
func IsSupportedFormat(format string) bool {
	format = strings.ToLower(strings.TrimSpace(format))
	return slices.Contains(supportedFormats, format)
}

// FormatList renders the accepted formats for flag help and error messages.
func FormatList() string {
	return strings.Join(supportedFormats, "|")
}

// Generate delegates reporting based on the requested format.
func Generate(report model.GapReport, format string, outFile string, limit int) error {
	return GenerateTo(report, format, outFile, limit, os.Stdout)
}

// GenerateTo is the writer-injectable form of Generate. Structured reports
// sent to stdout are written to stdout; file destinations retain their
// path-guarded file handling.
func GenerateTo(report model.GapReport, format string, outFile string, limit int, stdout io.Writer) error {
	if stdout == nil {
		stdout = os.Stdout
	}
	format = strings.ToLower(format)

	switch format {
	case "markdown":
		return generateMarkdown(report, outFile, limit, stdout)
	case "json":
		return generateJSON(report, outFile, stdout)
	case "csv":
		return generateCSV(report, outFile, stdout)
	case "html":
		return generateHTML(report, outFile, stdout)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"fmt"
	"strings"

	"github.com/had-nu/wardex/v3/pkg/catalog"
)

// unknownFrameworkTitle keeps the report truthful when a run carries no
// framework. Naming ISO 27001 here was the defect this replaces: every run
// produced an artefact titled "ISO 27001:2022" regardless of --framework.
const unknownFrameworkTitle = "Compliance & Release Gate Report"

// verifiedFrameworkName returns the framework title to print in the document
// heading. It only returns a title for a framework the catalogue recognises, or
// a display name the caller supplied explicitly. An unrecognised key is not a
// framework name and must not appear in a heading.
func verifiedFrameworkName(frameworkName, framework string) string {
	if trimmed := strings.TrimSpace(frameworkName); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(framework); trimmed != "" {
		if title, ok := catalog.DisplayName(trimmed); ok {
			return title
		}
	}
	return ""
}

// reportTitle builds the document heading. It never names a framework the run
// did not evaluate against, and never presents an unrecognised key as a title.
func reportTitle(frameworkName, framework string) string {
	display := verifiedFrameworkName(frameworkName, framework)
	if display == "" {
		return unknownFrameworkTitle
	}
	return display + " — Compliance & Release Gate Report"
}

// reportFrameworkLine states the framework explicitly so the reader can tell a
// titled report from an untitled one. An unrecognised key is reported as
// unrecognised rather than dropped or presented as a framework name.
func reportFrameworkLine(frameworkName, framework string) string {
	if display := verifiedFrameworkName(frameworkName, framework); display != "" {
		return display
	}
	if trimmed := strings.TrimSpace(framework); trimmed != "" {
		return fmt.Sprintf("%s (not a recognised framework)", trimmed)
	}
	return "not recorded for this run"
}

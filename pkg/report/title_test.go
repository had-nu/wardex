// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

func summaryWithFramework(framework, frameworkName string) model.GapReport {
	return model.GapReport{
		Summary: model.ExecutiveSummary{
			GeneratedAt:   time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
			Framework:     framework,
			FrameworkName: frameworkName,
			TotalControls: 1,
			CoveredCount:  1,
		},
		Findings: []model.Finding{{
			Control:    model.CatalogControl{ID: "A.8.8", Name: "Test control"},
			FinalScore: 1,
		}},
	}
}

// TestTitleNamesTheFrameworkThatRan is the regression guard for the defect where
// every report was titled "ISO 27001:2022" regardless of the framework,
// because GapReport carried no framework field.
func TestTitleNamesTheFrameworkThatRan(t *testing.T) {
	cases := []struct {
		framework     string
		frameworkName string
		want          string
	}{
		{"iso27001", "ISO/IEC 27001:2022", "ISO/IEC 27001:2022"},
		{"nis2", "NIS2", "NIS2"},
		{"dora", "DORA", "DORA"},
		{"nist_csf", "NIST CSF", "NIST CSF"},
		{"eu_ai_act", "EU AI Act", "EU AI Act"},
		{"soc2", "SOC 2", "SOC 2"},
	}

	for _, tc := range cases {
		t.Run(tc.framework, func(t *testing.T) {
			if got := reportTitle(tc.frameworkName, tc.framework); !strings.Contains(got, tc.want) {
				t.Errorf("reportTitle(%q, %q) = %q, want it to contain %q", tc.frameworkName, tc.framework, got, tc.want)
			}
			if got := reportTitle(tc.frameworkName, tc.framework); strings.Contains(got, "27001") && tc.framework != "iso27001" {
				t.Errorf("reportTitle for %s claims 27001: %q", tc.framework, got)
			}
		})
	}
}

// TestTitleResolvesDisplayNameFromFrameworkKey covers callers that set only the
// framework key and rely on the catalogue for the title.
func TestTitleResolvesDisplayNameFromFrameworkKey(t *testing.T) {
	if got := reportTitle("", "nis2"); !strings.Contains(got, "NIS2") {
		t.Errorf("reportTitle with only a framework key = %q, want the catalogue title", got)
	}
}

// TestTitleNeverInventsAFramework is the core guarantee: an unknown or absent
// framework must not be titled as a framework the run did not use.
func TestTitleNeverInventsAFramework(t *testing.T) {
	for _, tc := range []struct{ name, framework string }{
		{"absent", ""},
		{"blank", "   "},
		{"unknown", "not_a_framework"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := reportTitle("", tc.framework)
			if strings.Contains(got, "27001") || strings.Contains(got, "ISO") {
				t.Fatalf("reportTitle(%q) = %q, must not name ISO 27001", tc.framework, got)
			}
			if got != unknownFrameworkTitle {
				t.Errorf("reportTitle(%q) = %q, want %q", tc.framework, got, unknownFrameworkTitle)
			}
		})
	}
}

// TestFrameworkLineReportsUnrecognisedKey separates reporting the key from
// presenting it as a framework name. Dropping the key would hide a
// misconfiguration; putting it in the heading would assert a framework that
// does not exist.
func TestFrameworkLineReportsUnrecognisedKey(t *testing.T) {
	line := reportFrameworkLine("", "not_a_framework")
	if !strings.Contains(line, "not_a_framework") {
		t.Errorf("framework line %q drops the unrecognised key", line)
	}
	if !strings.Contains(line, "not a recognised framework") {
		t.Errorf("framework line %q must mark the key as unrecognised", line)
	}
	if got := reportTitle("", "not_a_framework"); strings.Contains(got, "not_a_framework") {
		t.Errorf("reportTitle %q must not present an unrecognised key as a framework name", got)
	}

	if got := reportFrameworkLine("", ""); got != "not recorded for this run" {
		t.Errorf("reportFrameworkLine with no framework = %q, want an explicit statement", got)
	}
}

// TestMarkdownReportCarriesFramework checks the emitted markdown, not just the
// helper, because the defect reached users through this generator.
func TestMarkdownReportCarriesFramework(t *testing.T) {
	for _, tc := range []struct{ framework, want string }{
		{"nis2", "NIS2"},
		{"dora", "DORA"},
	} {
		var out bytes.Buffer
		if err := GenerateTo(summaryWithFramework(tc.framework, ""), "markdown", "stdout", 10, &out); err != nil {
			t.Fatalf("GenerateTo: %v", err)
		}
		got := out.String()
		if !strings.Contains(got, tc.want) {
			t.Errorf("markdown for %s does not name %s:\n%s", tc.framework, tc.want, firstLine(got))
		}
		if strings.Contains(got, "27001") {
			t.Errorf("markdown for %s claims ISO 27001:\n%s", tc.framework, firstLine(got))
		}
	}
}

// TestHTMLReportCarriesFramework checks the HTML artefact path.
func TestHTMLReportCarriesFramework(t *testing.T) {
	var out bytes.Buffer
	if err := GenerateTo(summaryWithFramework("eu_ai_act", ""), "html", "stdout", 10, &out); err != nil {
		t.Fatalf("GenerateTo html: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "EU AI Act") {
		t.Errorf("html report does not name EU AI Act:\n%s", truncateForLog(got, 300))
	}
	if strings.Contains(got, "27001") {
		t.Errorf("html report claims ISO 27001:\n%s", truncateForLog(got, 300))
	}
}

// TestFormatRegistry checks the advertised format set.
func TestFormatRegistry(t *testing.T) {
	formats := SupportedFormats()
	if len(formats) != 4 {
		t.Errorf("SupportedFormats() = %v, want 4 formats", formats)
	}
	for _, format := range formats {
		if !IsSupportedFormat(format) {
			t.Errorf("IsSupportedFormat(%q) = false for a supported format", format)
		}
	}
	for _, unsupported := range []string{"", "pdf", "JSONL", "yml"} {
		if IsSupportedFormat(unsupported) {
			t.Errorf("IsSupportedFormat(%q) = true for an unsupported format", unsupported)
		}
	}
	if !strings.Contains(FormatList(), "html") {
		t.Errorf("FormatList() = %q, want it to advertise html", FormatList())
	}

	// The returned slice must not alias the registry.
	formats[0] = "mutated"
	if SupportedFormats()[0] == "mutated" {
		t.Error("SupportedFormats() returns the internal slice; callers can corrupt it")
	}
}

func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

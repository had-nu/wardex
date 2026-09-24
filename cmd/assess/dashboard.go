// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package assess

import (
	"fmt"
	"io"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

const maxAssessFindings = 5

func buildAssessSession(args []string) ui.SessionView {
	inputs := strings.Join(args, ", ")
	if inputs == "" {
		inputs = "—"
	}
	output := outputFormat
	if output == "" {
		output = "markdown"
	}
	assets := assetsFile
	if assets == "" {
		assets = "disabled"
	}
	snapshot := snapshotPath
	if snapshot == "" {
		snapshot = "disabled"
	}

	return ui.SessionView{
		Title:  "ASSESSMENT SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "INPUT", Value: inputs},
			{Label: "FRAMEWORK", Value: framework},
			{Label: "ASSETS", Value: assets},
			{Label: "SNAPSHOT", Value: snapshot},
			{Label: "OUTPUT", Value: output},
		},
	}
}

func buildAssessDashboard(session ui.SessionView, report model.GapReport, frameworkName string) ui.Dashboard {
	session.Title = "ASSESSMENT SESSION"
	session.Status = "COMPLETE"
	dashboard := ui.Dashboard{Session: session}

	limit := min(maxAssessFindings, len(report.Roadmap))
	for _, finding := range report.Roadmap[:limit] {
		dashboard.Findings = append(dashboard.Findings, buildAssessFinding(finding, frameworkName))
	}

	summary := report.Summary
	dashboard.Summary = ui.SummaryView{
		Decision: "COMPLETE",
		Fields: []ui.Field{
			{Label: "COVERAGE", Value: fmt.Sprintf("%.1f%%", summary.GlobalCoverage)},
			{Label: "TOTAL", Value: fmt.Sprintf("%d", summary.TotalControls)},
			{Label: "COVERED", Value: fmt.Sprintf("%d", summary.CoveredCount)},
			{Label: "PARTIAL", Value: fmt.Sprintf("%d", summary.PartialCount)},
			{Label: "GAPS", Value: fmt.Sprintf("%d", summary.GapCount)},
		},
	}
	if report.LayerDelta != nil {
		dashboard.Summary.Fields = append(dashboard.Summary.Fields,
			ui.Field{Label: "DOCUMENTED", Value: fmt.Sprintf("%d", report.LayerDelta.DocumentedCount)},
			ui.Field{Label: "IMPLEMENTED", Value: fmt.Sprintf("%d", report.LayerDelta.ImplementedCount)},
		)
	}
	if len(report.AssetCompliance) > 0 {
		dashboard.Summary.Fields = append(dashboard.Summary.Fields,
			ui.Field{Label: "ASSETS", Value: fmt.Sprintf("%d", len(report.AssetCompliance))},
		)
	}
	return dashboard
}

func buildAssessFinding(finding model.Finding, frameworkName string) ui.FindingView {
	title := finding.Control.Name
	if title == "" {
		title = finding.Control.ID
	}
	if title == "" {
		title = "Unnamed control"
	}

	reason := strings.Join(finding.GapReasons, "; ")
	if reason == "" {
		reason = "—"
	}
	recommendation := finding.Recommendation
	if recommendation == "" {
		recommendation = "—"
	}

	severity := "LOW"
	switch finding.Status {
	case model.StatusGap:
		severity = "HIGH"
	case model.StatusPartial:
		severity = "MEDIUM"
	case model.StatusCovered:
		severity = "LOW"
	}

	return ui.FindingView{
		Kind:       "COMPLIANCE GAP",
		Severity:   severity,
		Title:      title,
		Confidence: assessFindingConfidence(finding),
		Fields: []ui.Field{
			{Label: "CONTROL", Value: finding.Control.ID},
			{Label: "FRAMEWORK", Value: frameworkName},
			{Label: "STATUS", Value: strings.ToUpper(string(finding.Status))},
			{Label: "SCORE", Value: fmt.Sprintf("%.2f", finding.FinalScore)},
			{Label: "REASON", Value: reason},
			{Label: "ACTION", Value: recommendation},
		},
	}
}

func assessFindingConfidence(finding model.Finding) string {
	confidence := "N/A"
	rank := 0
	for _, mapping := range finding.CoveredBy {
		var candidate string
		var candidateRank int
		switch strings.ToLower(mapping.Confidence) {
		case "high":
			candidate, candidateRank = "HIGH", 3
		case "medium":
			candidate, candidateRank = "MEDIUM", 2
		case "low":
			candidate, candidateRank = "LOW", 1
		default:
			continue
		}
		if candidateRank > rank {
			confidence, rank = candidate, candidateRank
		}
	}
	return confidence
}

func renderAssessResults(w io.Writer, progress *ui.TerminalProgress, session ui.SessionView, report model.GapReport) {
	dashboard := buildAssessDashboard(session, report, framework)
	if progress != nil && progress.Enabled() {
		_ = ui.RenderResults(w, dashboard)
		return
	}
	_ = ui.RenderDashboard(w, dashboard)
}

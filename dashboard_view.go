// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"fmt"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/orchestrator"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

const maxDashboardFindings = 5

func buildEvaluationSession(opts orchestrator.EvaluationOptions) ui.SessionView {
	inputs := strings.Join(opts.Inputs, ", ")
	if inputs == "" {
		inputs = "—"
	}
	outputFormat := opts.OutputFormat
	if outputFormat == "" {
		outputFormat = "markdown"
	}
	profile := opts.ProfileName
	if profile == "" {
		profile = "default"
	}
	snapshot := "disabled"
	if !opts.NoSnapshot {
		snapshot = opts.SnapshotFile
		if snapshot == "" {
			snapshot = "enabled"
		}
	}
	gate := "disabled"
	if opts.GateFile != "" {
		gate = opts.GateFile
	}

	return ui.SessionView{
		Title:  "EVALUATION SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "INPUT", Value: inputs},
			{Label: "FRAMEWORK", Value: opts.Framework},
			{Label: "PROFILE", Value: profile},
			{Label: "OUTPUT", Value: outputFormat},
			{Label: "CONFIDENCE", Value: opts.MinConfidence},
			{Label: "SNAPSHOT", Value: snapshot},
			{Label: "GATE", Value: gate},
		},
	}
}

func buildEvaluationDashboard(opts orchestrator.EvaluationOptions, result *orchestrator.EvaluationResult) ui.Dashboard {
	if result == nil {
		return ui.Dashboard{}
	}

	outputFormat := opts.OutputFormat
	if outputFormat == "" {
		outputFormat = "markdown"
	}
	snapshot := "disabled"
	if !opts.NoSnapshot {
		snapshot = opts.SnapshotFile
		if snapshot == "" {
			snapshot = "enabled"
		}
	}

	decision := "PASS"
	if result.GateReport != nil {
		decision = strings.ToUpper(string(result.GateReport.OverallDecision))
	} else if result.ExitReason == orchestrator.ExitCompliance {
		decision = "FAIL"
	}

	dashboard := ui.Dashboard{
		Session: func() ui.SessionView {
			session := buildEvaluationSession(opts)
			session.Status = "COMPLETE"
			return session
		}(),
		Phases: []ui.PhaseView{
			{Number: 1, Name: "Loading configuration", Status: "DONE", Detail: "configuration loaded"},
			{Number: 2, Name: "Loading controls", Status: "DONE", Detail: fmt.Sprintf("%d input file(s)", len(opts.Inputs))},
			{Number: 3, Name: "Matching framework controls", Status: "DONE", Detail: fmt.Sprintf("%d finding(s)", len(result.Report.Findings))},
			{Number: 4, Name: "Computing gaps and coverage", Status: "DONE", Detail: fmt.Sprintf("%d finding(s)", len(result.Report.Findings))},
			{Number: 5, Name: "Building roadmap and summary", Status: "DONE", Detail: fmt.Sprintf("%d roadmap item(s)", len(result.Report.Roadmap))},
			{Number: 6, Name: "Evaluating release gate", Status: gatePhaseStatus(result.GateReport), Detail: gatePhaseDetail(result.GateReport)},
			{Number: 7, Name: "Processing snapshot", Status: snapshotPhaseStatus(opts), Detail: snapshot},
			{Number: 8, Name: "Generating report", Status: "DONE", Detail: outputFormat},
			{Number: 9, Name: "Determining release decision", Status: "DONE", Detail: decision},
		},
	}

	limit := opts.RoadmapLimit
	if limit <= 0 || limit > maxDashboardFindings {
		limit = maxDashboardFindings
	}
	for _, finding := range result.Report.Roadmap[:min(limit, len(result.Report.Roadmap))] {
		dashboard.Findings = append(dashboard.Findings, buildFindingView(finding, opts.Framework))
	}

	summary := result.Report.Summary
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "COVERAGE", Value: fmt.Sprintf("%.1f%%", summary.GlobalCoverage)},
			{Label: "COVERED", Value: fmt.Sprintf("%d", summary.CoveredCount)},
			{Label: "PARTIAL", Value: fmt.Sprintf("%d", summary.PartialCount)},
			{Label: "GAPS", Value: fmt.Sprintf("%d", summary.GapCount)},
			{Label: "EXIT CODE", Value: fmt.Sprintf("%d", result.ExitCode)},
		},
	}
	if opts.OutFile != "" && opts.OutFile != "stdout" {
		dashboard.Summary.Fields = append(dashboard.Summary.Fields, ui.Field{Label: "REPORT", Value: opts.OutFile})
	}

	return dashboard
}

func buildFindingView(finding model.Finding, framework string) ui.FindingView {
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

	return ui.FindingView{
		Kind:       "COMPLIANCE GAP",
		Severity:   findingSeverity(finding),
		Title:      title,
		Confidence: findingConfidence(finding),
		Fields: []ui.Field{
			{Label: "CONTROL", Value: finding.Control.ID},
			{Label: "FRAMEWORK", Value: framework},
			{Label: "STATUS", Value: strings.ToUpper(string(finding.Status))},
			{Label: "SCORE", Value: fmt.Sprintf("%.2f", finding.FinalScore)},
			{Label: "REASON", Value: reason},
			{Label: "ACTION", Value: recommendation},
		},
	}
}

func findingSeverity(finding model.Finding) string {
	switch finding.Status {
	case model.StatusGap:
		return "HIGH"
	case model.StatusPartial:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func findingConfidence(finding model.Finding) string {
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

func gatePhaseStatus(report *model.GateReport) string {
	if report == nil {
		return "SKIPPED"
	}
	return "DONE"
}

func gatePhaseDetail(report *model.GateReport) string {
	if report == nil {
		return "not requested"
	}
	return strings.ToUpper(string(report.OverallDecision))
}

func snapshotPhaseStatus(opts orchestrator.EvaluationOptions) string {
	if opts.NoSnapshot {
		return "SKIPPED"
	}
	return "DONE"
}

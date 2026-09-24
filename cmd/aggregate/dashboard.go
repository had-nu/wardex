// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package aggregate

import (
	"fmt"
	"io"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/ui"
)

func buildAggregateSession(args []string) ui.SessionView {
	inputs := strings.Join(args, ", ")
	if inputs == "" {
		inputs = "—"
	}
	return ui.SessionView{
		Title:  "AGGREGATION SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "INPUTS", Value: inputs},
			{Label: "POLICY", Value: failOn},
			{Label: "SOURCES", Value: fmt.Sprintf("%d", len(args))},
		},
	}
}

func aggregateDecision(results []fileResult, policy string) (combined string, blockCount int, blocked bool) {
	if len(results) == 0 {
		return "ALLOW", 0, false
	}
	for _, result := range results {
		if strings.EqualFold(result.decision, "block") {
			blockCount++
		}
	}

	blocked = blockCount > 0
	if policy == "all-block" {
		blocked = blockCount == len(results)
	}
	if blocked {
		return "BLOCK", blockCount, true
	}
	return "ALLOW", blockCount, false
}

func buildAggregateDashboard(session ui.SessionView, results []fileResult, policy string) ui.Dashboard {
	combined, blockCount, _ := aggregateDecision(results, policy)
	session.Title = "AGGREGATION SESSION"
	session.Status = "COMPLETE"

	dashboard := ui.Dashboard{Session: session}
	for _, result := range results {
		dashboard.Findings = append(dashboard.Findings, buildAggregateFinding(result))
	}
	dashboard.Summary = ui.SummaryView{
		Decision: combined,
		Fields: []ui.Field{
			{Label: "SOURCES", Value: fmt.Sprintf("%d", len(results))},
			{Label: "BLOCKED", Value: fmt.Sprintf("%d", blockCount)},
			{Label: "POLICY", Value: policy},
		},
	}
	return dashboard
}

func buildAggregateFinding(result fileResult) ui.FindingView {
	severity := "LOW"
	switch strings.ToLower(result.decision) {
	case "block":
		severity = "HIGH"
	case "warn":
		severity = "MEDIUM"
	}

	return ui.FindingView{
		Kind:     "AGGREGATED GATE",
		Severity: severity,
		Title:    result.file,
		Fields: []ui.Field{
			{Label: "DECISION", Value: strings.ToUpper(result.decision)},
			{Label: "BLOCKED", Value: fmt.Sprintf("%d", result.blocked)},
			{Label: "ALLOWED", Value: fmt.Sprintf("%d", result.allowed)},
			{Label: "WARNED", Value: fmt.Sprintf("%d", result.warned)},
		},
	}
}

func renderAggregateResults(w io.Writer, progress *ui.TerminalProgress, session ui.SessionView, results []fileResult) {
	dashboard := buildAggregateDashboard(session, results, failOn)
	if progress != nil && progress.Enabled() {
		_ = ui.RenderResults(w, dashboard)
		return
	}
	_ = ui.RenderDashboard(w, dashboard)
}

func renderAggregateTable(w io.Writer, results []fileResult) {
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "## Wardex — Aggregate Gate Decision")
	_, _ = fmt.Fprintln(w, "")

	table := ui.NewTable(
		[]string{"File", "Decision", "Blocked", "Allowed", "Warned"},
		[]int{40, 10, 8, 8, 8},
	)
	for _, result := range results {
		label := strings.ToUpper(result.decision)
		var background string
		switch strings.ToLower(result.decision) {
		case "block":
			background = ui.BgRed
		case "warn":
			background = ui.BgYellow
		default:
			background = ui.BgGreen
		}
		table.AddRowStyled(
			[]string{result.file, label, fmt.Sprintf("%d", result.blocked), fmt.Sprintf("%d", result.allowed), fmt.Sprintf("%d", result.warned)},
			nil,
			[]string{"", background, "", "", ""},
		)
	}
	table.Render(w)
}

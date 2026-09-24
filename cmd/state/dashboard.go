// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package state

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/statestore"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type stateUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func stateCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginStateUI(cmd *cobra.Command, command, path string) *stateUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := stateCommandOutput(cmd)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "STATE STORE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "STATE DIR", Value: path},
		},
	})
	return &stateUI{
		progress:          progress,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *stateUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *stateUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *stateUI) render(dashboard ui.Dashboard) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func stateDecisionSeverity(decision model.Decision) string {
	switch decision {
	case model.DecisionBlock:
		return "HIGH"
	case model.DecisionWarn:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func stateDecision(decision model.Decision) string {
	return strings.ToUpper(string(decision))
}

func buildStateUnavailableDashboard(path string) ui.Dashboard {
	return ui.Dashboard{Summary: ui.SummaryView{
		Decision: "NOT_INITIALIZED",
		Fields: []ui.Field{
			{Label: "STATE DIR", Value: path},
			{Label: "NEXT", Value: "wardex evaluate"},
		},
	}}
}

func buildStateStatusDashboard(path string, state *statestore.State, chainErr error) ui.Dashboard {
	if state == nil || state.LastRun.IsZero() {
		return ui.Dashboard{Summary: ui.SummaryView{
			Decision: "EMPTY",
			Fields: []ui.Field{
				{Label: "STATE DIR", Value: path},
				{Label: "NEXT", Value: "wardex evaluate"},
			},
		}}
	}
	decision := "READY"
	severity := "LOW"
	if chainErr != nil {
		decision = "BROKEN"
		severity = "HIGH"
	}
	fields := []ui.Field{
		{Label: "STATE DIR", Value: path},
		{Label: "VERSION", Value: state.Version},
		{Label: "LAST RUN", Value: state.LastRun.UTC().Format(time.RFC3339)},
		{Label: "LAST DECISION", Value: stateDecision(state.LastDecision)},
		{Label: "RISK SCORE", Value: fmt.Sprintf("%.1f%%", state.LastRisk*100)},
		{Label: "TOTAL RUNS", Value: fmt.Sprintf("%d", state.RunCount)},
		{Label: "ACTIVE ACCEPTS", Value: fmt.Sprintf("%d", state.ActiveAccepts)},
	}
	if len(state.ExpiringSoon) > 0 {
		fields = append(fields, ui.Field{Label: "EXPIRING SOON", Value: strings.Join(state.ExpiringSoon, ", ")})
	}
	if chainErr != nil {
		fields = append(fields, ui.Field{Label: "CHAIN ERROR", Value: chainErr.Error()})
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "STATE INTEGRITY",
			Severity: severity,
			Title:    decision,
			Fields:   fields,
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "STATE DIR", Value: path},
				{Label: "DECISION", Value: stateDecision(state.LastDecision)},
				{Label: "RISK", Value: fmt.Sprintf("%.1f%%", state.LastRisk*100)},
			},
		},
	}
}

func buildStateHistoryDashboard(path string, records []statestore.HistoryRecord) ui.Dashboard {
	dashboard := ui.Dashboard{}
	allow, warn, block := 0, 0, 0
	for _, record := range records {
		if record.State == nil {
			continue
		}
		switch record.State.LastDecision {
		case model.DecisionAllow:
			allow++
		case model.DecisionWarn:
			warn++
		case model.DecisionBlock:
			block++
		}
		if len(dashboard.Findings) >= 25 {
			continue
		}
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "STATE HISTORY",
			Severity: stateDecisionSeverity(record.State.LastDecision),
			Title:    record.Timestamp.UTC().Format("2006-01-02 15:04 UTC"),
			Fields: []ui.Field{
				{Label: "DATE", Value: record.Timestamp.UTC().Format(time.RFC3339)},
				{Label: "DECISION", Value: stateDecision(record.State.LastDecision)},
				{Label: "RISK", Value: fmt.Sprintf("%.1f%%", record.State.LastRisk*100)},
				{Label: "VULNERABILITIES", Value: fmt.Sprintf("%d", trendVulnCount(record.State.Trend))},
				{Label: "ACTIVE ACCEPTS", Value: fmt.Sprintf("%d", record.State.ActiveAccepts)},
			},
		})
	}
	decision := "READY"
	if block > 0 {
		decision = "REVIEW"
	}
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "STATE DIR", Value: path},
			{Label: "RECORDS", Value: fmt.Sprintf("%d", len(records))},
			{Label: "ALLOW", Value: fmt.Sprintf("%d", allow)},
			{Label: "WARN", Value: fmt.Sprintf("%d", warn)},
			{Label: "BLOCK", Value: fmt.Sprintf("%d", block)},
		},
	}
	return dashboard
}

func buildStateTrendDashboard(path string, analysis *statestore.TrendAnalysis, history []statestore.TrendPoint) ui.Dashboard {
	if analysis == nil {
		analysis = &statestore.TrendAnalysis{Direction: statestore.TrendStable}
	}
	dashboard := ui.Dashboard{}
	for _, point := range recentTrendPoints(history, 10) {
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "RISK TREND",
			Severity: stateDecisionSeverity(point.Decision),
			Title:    point.Date.UTC().Format("2006-01-02"),
			Fields: []ui.Field{
				{Label: "DATE", Value: point.Date.UTC().Format(time.RFC3339)},
				{Label: "RISK", Value: fmt.Sprintf("%.1f%%", point.Risk*100)},
				{Label: "DECISION", Value: stateDecision(point.Decision)},
				{Label: "VULNERABILITIES", Value: fmt.Sprintf("%d", point.VulnCount)},
			},
		})
	}
	decision := "STABLE"
	switch analysis.Direction {
	case statestore.TrendImproving:
		decision = "IMPROVING"
	case statestore.TrendWorsening:
		decision = "WORSENING"
	case statestore.TrendStable:
		decision = "STABLE"
	}
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "STATE DIR", Value: path},
			{Label: "RUNS", Value: fmt.Sprintf("%d", analysis.TotalRuns)},
			{Label: "AVERAGE RISK", Value: fmt.Sprintf("%.1f%%", analysis.AverageRisk*100)},
			{Label: "RISK DELTA", Value: fmt.Sprintf("%+.1f%%", analysis.RiskDelta*100)},
			{Label: "ALLOW/WARN/BLOCK", Value: fmt.Sprintf("%d/%d/%d", analysis.AllowCount, analysis.WarnCount, analysis.BlockCount)},
		},
	}
	return dashboard
}

func buildStateDashboardDashboard(path string, state *statestore.State, analysis *statestore.TrendAnalysis) ui.Dashboard {
	if state == nil || state.LastRun.IsZero() {
		return buildStateStatusDashboard(path, state, nil)
	}
	dashboard := buildStateStatusDashboard(path, state, nil)
	trend := buildStateTrendDashboard(path, analysis, state.Trend)
	dashboard.Findings = append(dashboard.Findings, trend.Findings...)
	dashboard.Summary = trend.Summary
	return dashboard
}

func buildStateVerifyDashboard(path string, entries int, first, last time.Time, verifyErr error) ui.Dashboard {
	decision := "INTACT"
	severity := "LOW"
	if verifyErr != nil {
		decision = "BROKEN"
		severity = "HIGH"
	}
	fields := []ui.Field{
		{Label: "STATE DIR", Value: path},
		{Label: "CHAIN ENTRIES", Value: fmt.Sprintf("%d", entries)},
	}
	if !first.IsZero() {
		fields = append(fields,
			ui.Field{Label: "FIRST ENTRY", Value: first.UTC().Format(time.RFC3339)},
			ui.Field{Label: "LAST ENTRY", Value: last.UTC().Format(time.RFC3339)},
		)
	}
	if verifyErr != nil {
		fields = append(fields, ui.Field{Label: "ERROR", Value: verifyErr.Error()})
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "STATE CHAIN",
			Severity: severity,
			Title:    decision,
			Fields:   fields,
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "STATE DIR", Value: path},
				{Label: "ENTRIES", Value: fmt.Sprintf("%d", entries)},
			},
		},
	}
}

func buildStateCleanupDashboard(path string, retentionDays int) ui.Dashboard {
	return ui.Dashboard{Summary: ui.SummaryView{
		Decision: "CLEANED",
		Fields: []ui.Field{
			{Label: "STATE DIR", Value: path},
			{Label: "RETENTION", Value: fmt.Sprintf("%d days", retentionDays)},
		},
	}}
}

func recentTrendPoints(points []statestore.TrendPoint, limit int) []statestore.TrendPoint {
	if len(points) <= limit {
		return points
	}
	return points[len(points)-limit:]
}

func trendVulnCount(points []statestore.TrendPoint) int {
	total := 0
	for _, point := range points {
		total += point.VulnCount
	}
	return total
}

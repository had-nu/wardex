// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/orchestrator"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

const maxGateDashboardDecisions = 5

func buildGateSession(opts orchestrator.GateOptions) ui.SessionView {
	controls := strings.Join(opts.Controls, ", ")
	if controls == "" {
		controls = "—"
	}
	profile := opts.ProfileName
	if profile == "" {
		profile = "default"
	}
	output := opts.OutputFormat
	if output == "" {
		output = "markdown"
	}
	gateMode := opts.GateMode
	if gateMode == "" {
		gateMode = "any"
	}
	gateClass := opts.GateClass
	if gateClass == "" {
		gateClass = "deploy"
	}

	evidence := opts.GateFile
	if evidence == "" {
		evidence = "—"
	}
	config := opts.ConfigPath
	if config == "" {
		config = "—"
	}

	return ui.SessionView{
		Title:  "RELEASE GATE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "CONTROLS", Value: controls},
			{Label: "EVIDENCE", Value: evidence},
			{Label: "CONFIG", Value: config},
			{Label: "PROFILE", Value: profile},
			{Label: "MODE", Value: gateMode},
			{Label: "CLASS", Value: gateClass},
			{Label: "OUTPUT", Value: output},
		},
	}
}

func buildGateDashboard(opts orchestrator.GateOptions, report model.GateReport) ui.Dashboard {
	decisions := append([]model.ReleaseDecision(nil), report.Decisions...)
	sort.SliceStable(decisions, func(i, j int) bool {
		return decisions[i].ReleaseRisk > decisions[j].ReleaseRisk
	})
	if len(decisions) > maxGateDashboardDecisions {
		decisions = decisions[:maxGateDashboardDecisions]
	}

	dashboard := ui.Dashboard{
		Session: func() ui.SessionView {
			session := buildGateSession(opts)
			session.Status = "COMPLETE"
			return session
		}(),
	}
	for _, item := range decisions {
		dashboard.Findings = append(dashboard.Findings, buildGateFinding(item))
	}

	decision := strings.ToUpper(string(report.OverallDecision))
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "BLOCKED", Value: fmt.Sprintf("%d", report.BlockedCount)},
			{Label: "ALLOWED", Value: fmt.Sprintf("%d", report.AllowedCount)},
			{Label: "WARNINGS", Value: fmt.Sprintf("%d", report.WarnCount)},
			{Label: "HIGHEST RISK", Value: fmt.Sprintf("%.2f", report.HighestRisk)},
			{Label: "GATE MATURITY", Value: fmt.Sprintf("%d", report.GateMaturityLevel)},
		},
	}
	return dashboard
}

func buildGateFinding(item model.ReleaseDecision) ui.FindingView {
	vulnerability := item.Vulnerability
	title := vulnerability.CVEID
	if title == "" {
		title = vulnerability.Component
	}
	if title == "" {
		title = "Unnamed vulnerability"
	}

	severity := "LOW"
	switch item.Decision {
	case model.DecisionBlock:
		severity = "HIGH"
	case model.DecisionWarn:
		severity = "MEDIUM"
	case model.DecisionAllow:
		severity = "LOW"
	}

	epss := "unknown"
	if vulnerability.EPSSScore > 0 {
		epss = fmt.Sprintf("%.2f", vulnerability.EPSSScore)
	}
	reachable := "no"
	if vulnerability.Reachable {
		reachable = "yes"
	}

	return ui.FindingView{
		Kind:     "RELEASE GATE DECISION",
		Severity: severity,
		Title:    title,
		Fields: []ui.Field{
			{Label: "CVE", Value: vulnerability.CVEID},
			{Label: "COMPONENT", Value: vulnerability.Component},
			{Label: "DECISION", Value: strings.ToUpper(string(item.Decision))},
			{Label: "RELEASE RISK", Value: fmt.Sprintf("%.2f", item.ReleaseRisk)},
			{Label: "CVSS", Value: fmt.Sprintf("%.1f", vulnerability.CVSSBase)},
			{Label: "EPSS", Value: epss},
			{Label: "REACHABLE", Value: reachable},
		},
	}
}

func renderGateResults(w io.Writer, progress *ui.TerminalProgress, opts orchestrator.GateOptions, report model.GateReport) {
	dashboard := buildGateDashboard(opts, report)
	if progress != nil && progress.Enabled() {
		_ = ui.RenderResults(w, dashboard)
		return
	}
	_ = ui.RenderDashboard(w, dashboard)
}

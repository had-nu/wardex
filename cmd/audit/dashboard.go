// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package audit

import (
	"fmt"
	"io"
	"strings"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type auditUI struct {
	progress *ui.TerminalProgress
	session  ui.SessionView
	stderr   io.Writer
}

func beginAuditUI(cmd *cobra.Command, command, detail string) *auditUI {
	stderr := cmd.ErrOrStderr()
	session := ui.SessionView{
		Title:  "AUDIT VERIFICATION SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "TARGET", Value: detail},
		},
	}
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(session)
	return &auditUI{progress: progress, session: session, stderr: stderr}
}

func (u *auditUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *auditUI) render(dashboard ui.Dashboard) {
	if u == nil || u.progress == nil || !u.progress.Enabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func buildChainVerifyDashboard(path, sessionFilter string, report cpl.VerifyReport) ui.Dashboard {
	decision := "INTACT"
	severity := "LOW"
	if !report.Valid {
		decision = "TAMPERED"
		severity = "HIGH"
	}
	dashboard := ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "AUDIT LOG", Value: path},
				{Label: "SESSION", Value: sessionLabel(sessionFilter)},
				{Label: "SEGMENTS", Value: fmt.Sprintf("%d", len(report.Segments))},
				{Label: "ENTRIES", Value: fmt.Sprintf("%d", report.Entries)},
			},
		},
	}
	for i, segment := range report.Segments {
		if !segment.Valid {
			dashboard.Findings = append(dashboard.Findings, ui.FindingView{
				Kind:     "AUDIT CHAIN SEGMENT",
				Severity: severity,
				Title:    fmt.Sprintf("Segment %d", i+1),
				Fields: []ui.Field{
					{Label: "STATUS", Value: decision},
					{Label: "ENTRIES", Value: fmt.Sprintf("%d", segment.Entries)},
				},
			})
		}
	}
	return dashboard
}

func buildLinkVerifyDashboard(path string, total, ok, mismatch, missing, schema int, results []cpl.LinkResult) ui.Dashboard {
	decision := "LINKED"
	severity := "LOW"
	if mismatch+missing+schema > 0 {
		decision = "DIVERGENT"
		severity = "HIGH"
	}
	dashboard := ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "AUDIT LOG", Value: path},
				{Label: "TOTAL", Value: fmt.Sprintf("%d", total)},
				{Label: "OK", Value: fmt.Sprintf("%d", ok)},
				{Label: "MISMATCH", Value: fmt.Sprintf("%d", mismatch)},
				{Label: "MISSING", Value: fmt.Sprintf("%d", missing)},
				{Label: "SCHEMA", Value: fmt.Sprintf("%d", schema)},
			},
		},
	}
	for i, result := range results {
		if result.Status == cpl.StatusOK {
			continue
		}
		if i >= 10 {
			break
		}
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "CONFIG LINK DIVERGENCE",
			Severity: severity,
			Title:    string(result.Status),
			Fields: []ui.Field{
				{Label: "CONFIG", Value: result.ConfigFile},
				{Label: "RECORDED", Value: result.RecordedHash},
				{Label: "COMPUTED", Value: result.ComputedHash},
			},
		})
	}
	return dashboard
}

func sessionLabel(session string) string {
	if session == "" {
		return "all"
	}
	return session
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trustcmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type trustUI struct {
	progress          *ui.TerminalProgress
	session           ui.SessionView
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func trustCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginTrustUI(cmd *cobra.Command, command, path string) *trustUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := trustCommandOutput(cmd)
	session := ui.SessionView{
		Title:  "TRUST STORE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "STORE", Value: path},
		},
	}
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(session)
	return &trustUI{
		progress:          progress,
		session:           session,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *trustUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *trustUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *trustUI) render(dashboard ui.Dashboard) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func buildTrustListDashboard(store *trust.TrustStore, path string) ui.Dashboard {
	revoked := trust.RevokedKeySet(store)
	active, revokedCount, _ := trust.KeyStats(store)
	dashboard := ui.Dashboard{}
	for _, entry := range store.Keys {
		status := "ACTIVE"
		severity := "LOW"
		if revoked[entry.ID] {
			status = "REVOKED"
			severity = "HIGH"
		}
		title := entry.Name
		if title == "" {
			title = entry.Actor
		}
		if title == "" {
			title = entry.ID
		}
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "TRUST KEY ENTRY",
			Severity: severity,
			Title:    title,
			Fields: []ui.Field{
				{Label: "KEY ID", Value: entry.ID},
				{Label: "ACTOR", Value: entry.Actor},
				{Label: "ROLE", Value: strings.ToUpper(string(entry.Role))},
				{Label: "STATUS", Value: status},
				{Label: "ADDED", Value: entry.AddedAt.Format("2006-01-02 15:04 UTC")},
			},
		})
	}
	decision := "READY"
	if revokedCount > 0 {
		decision = "REVIEW"
	}
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "STORE", Value: path},
			{Label: "TOTAL", Value: fmt.Sprintf("%d", len(store.Keys))},
			{Label: "ACTIVE", Value: fmt.Sprintf("%d", active)},
			{Label: "REVOKED", Value: fmt.Sprintf("%d", revokedCount)},
		},
	}
	return dashboard
}

func buildTrustDetailDashboard(entry trust.KeyEntry, status, path string) ui.Dashboard {
	severity := "LOW"
	decision := "READY"
	if status == "revoked" {
		severity = "HIGH"
		decision = "REVOKED"
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "TRUST KEY ENTRY",
			Severity: severity,
			Title:    entry.Name,
			Fields: []ui.Field{
				{Label: "KEY ID", Value: entry.ID},
				{Label: "ACTOR", Value: entry.Actor},
				{Label: "ROLE", Value: strings.ToUpper(string(entry.Role))},
				{Label: "STATUS", Value: strings.ToUpper(status)},
				{Label: "ADDED", Value: entry.AddedAt.Format("2006-01-02 15:04 UTC")},
				{Label: "ADDED BY", Value: entry.AddedBy},
				{Label: "STORE", Value: path},
			},
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "KEY ID", Value: entry.ID},
				{Label: "STATUS", Value: strings.ToUpper(status)},
			},
		},
	}
}

func buildTrustActionDashboard(command, path string, fields []ui.Field) ui.Dashboard {
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: strings.ToUpper(command),
			Fields:   append([]ui.Field{{Label: "STORE", Value: path}}, fields...),
		},
	}
}

func boolLabel(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func buildTrustVerifyDashboard(path, adminID string, total, active, revoked int, valid bool) ui.Dashboard {
	decision := "VALID"
	severity := "LOW"
	if !valid {
		decision = "INVALID"
		severity = "HIGH"
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "TRUST ROOT SIGNATURE",
			Severity: severity,
			Title:    decision,
			Fields: []ui.Field{
				{Label: "ROOT SIGNATURE", Value: decision},
				{Label: "ADMIN KEY", Value: adminID},
			},
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "STORE", Value: path},
				{Label: "TOTAL", Value: fmt.Sprintf("%d", total)},
				{Label: "ACTIVE", Value: fmt.Sprintf("%d", active)},
				{Label: "REVOKED", Value: fmt.Sprintf("%d", revoked)},
			},
		},
	}
}

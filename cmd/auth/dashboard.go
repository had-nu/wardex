// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package auth

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type authUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func authCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginAuthUI(cmd *cobra.Command, command, detail string) *authUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := authCommandOutput(cmd)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "AUTHENTICATION SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "TARGET", Value: detail},
		},
	})
	return &authUI{
		progress:          progress,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *authUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *authUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *authUI) render(dashboard ui.Dashboard) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func authColor(w io.Writer, value, color string) string {
	if w == nil || ui.DetectProfile(w).ColorDepth == ui.ColorNone {
		return value
	}
	return ui.Colorize(value, color)
}

func buildAuthStatusDashboard(path string, active, revoked int, adminID string, verifyErr error) ui.Dashboard {
	decision := "VALID"
	severity := "LOW"
	fields := []ui.Field{
		{Label: "TRUST STORE", Value: path},
		{Label: "ACTIVE KEYS", Value: fmt.Sprintf("%d", active)},
		{Label: "REVOKED", Value: fmt.Sprintf("%d", revoked)},
		{Label: "ADMIN KEY", Value: adminID},
	}
	if verifyErr != nil {
		decision = "INVALID"
		severity = "HIGH"
		fields = append(fields, ui.Field{Label: "ERROR", Value: verifyErr.Error()})
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "TRUST ROOT SIGNATURE",
			Severity: severity,
			Title:    decision,
			Fields:   fields,
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "STORE", Value: path},
				{Label: "ACTIVE", Value: fmt.Sprintf("%d", active)},
				{Label: "REVOKED", Value: fmt.Sprintf("%d", revoked)},
			},
		},
	}
}

func buildAuthVerifyDashboard(path string, entry trust.KeyEntry, revoked bool) ui.Dashboard {
	decision := "ACTIVE"
	severity := "LOW"
	status := "ACTIVE"
	if revoked {
		decision = "REVOKED"
		severity = "HIGH"
		status = "REVOKED"
	}
	permissions := trust.RolePermissions[entry.Role]
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "ACTOR KEY",
			Severity: severity,
			Title:    status,
			Fields: []ui.Field{
				{Label: "ACTOR", Value: entry.Actor},
				{Label: "KEY ID", Value: entry.ID},
				{Label: "NAME", Value: entry.Name},
				{Label: "ROLE", Value: strings.ToUpper(string(entry.Role))},
				{Label: "STATUS", Value: status},
				{Label: "PERMISSIONS", Value: fmt.Sprintf("%d", len(permissions))},
				{Label: "STORE", Value: path},
			},
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "ACTOR", Value: entry.Actor},
				{Label: "KEY ID", Value: entry.ID},
				{Label: "STATUS", Value: status},
			},
		},
	}
}

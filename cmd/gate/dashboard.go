// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package gatecmd

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type gateUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func gateCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginGateUI(cmd *cobra.Command, command, auditLog, version string) *gateUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := gateCommandOutput(cmd)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "RELEASE GATE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "AUDIT LOG", Value: auditLog},
			{Label: "VERSION", Value: version},
		},
	})
	return &gateUI{
		progress:          progress,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *gateUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *gateUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *gateUI) render(dashboard ui.Dashboard) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func buildGateCheckDashboard(auditLog, version, decision, policyRef string, sealedAt time.Time, entryHash string, registryFresh bool) ui.Dashboard {
	severity := "LOW"
	if decision == "DUPLICATE" || decision == "ERROR" {
		severity = "HIGH"
	}
	fields := []ui.Field{
		{Label: "AUDIT LOG", Value: auditLog},
		{Label: "VERSION", Value: version},
		{Label: "REGISTRY", Value: map[bool]string{true: "fresh", false: "rebuilt"}[registryFresh]},
	}
	if policyRef != "" {
		fields = append(fields, ui.Field{Label: "POLICY REF", Value: policyRef})
	}
	if !sealedAt.IsZero() {
		fields = append(fields, ui.Field{Label: "SEALED AT", Value: sealedAt.UTC().Format(time.RFC3339)})
	}
	if entryHash != "" {
		fields = append(fields, ui.Field{Label: "ENTRY HASH", Value: entryHash})
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "RELEASE VERSION",
			Severity: severity,
			Title:    decision,
			Fields:   fields,
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "VERSION", Value: version},
				{Label: "STATUS", Value: decision},
				{Label: "AUDIT LOG", Value: auditLog},
			},
		},
	}
}

func buildGateErrorDashboard(auditLog, version, detail string) ui.Dashboard {
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "RELEASE VERSION",
			Severity: "HIGH",
			Title:    "ERROR",
			Fields: []ui.Field{
				{Label: "AUDIT LOG", Value: auditLog},
				{Label: "VERSION", Value: version},
				{Label: "ERROR", Value: detail},
			},
		}},
		Summary: ui.SummaryView{
			Decision: "ERROR",
			Fields: []ui.Field{
				{Label: "VERSION", Value: version},
				{Label: "STATUS", Value: "ERROR"},
			},
		},
	}
}

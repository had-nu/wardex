// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package contract

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type contractUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func contractCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginContractUI(cmd *cobra.Command, path string) *contractUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := contractCommandOutput(cmd)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "CONTRACT INTEGRITY SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{{Label: "CONTRACT", Value: path}},
	})
	return &contractUI{
		progress:          progress,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *contractUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *contractUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *contractUI) render(dashboard ui.Dashboard) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func buildContractDashboard(path, hash string, size int, modified time.Time, expected, status string) ui.Dashboard {
	decision := strings.ToUpper(status)
	severity := "LOW"
	switch decision {
	case "MISMATCH":
		severity = "HIGH"
	case "COMPUTED":
		decision = "COMPUTED"
	}
	fields := []ui.Field{
		{Label: "CONTRACT", Value: path},
		{Label: "SHA-256", Value: hash},
		{Label: "SIZE", Value: fmt.Sprintf("%d bytes", size)},
		{Label: "LAST MODIFIED", Value: modified.UTC().Format(time.RFC3339)},
		{Label: "STATUS", Value: decision},
	}
	if expected != "" {
		fields = append(fields, ui.Field{Label: "EXPECTED", Value: expected})
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "CONTRACT INTEGRITY",
			Severity: severity,
			Title:    decision,
			Fields:   fields,
		}},
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "CONTRACT", Value: path},
				{Label: "STATUS", Value: decision},
				{Label: "SHA-256", Value: hash},
			},
		},
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package convert

import (
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type convertUI struct {
	progress *ui.TerminalProgress
	stderr   io.Writer
}

func commandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginConvertUI(cmd *cobra.Command, command, input, output string) *convertUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "CONVERTER SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: command},
			{Label: "INPUT", Value: input},
			{Label: "OUTPUT", Value: output},
		},
	})
	return &convertUI{progress: progress, stderr: stderr}
}

func (u *convertUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func exploitedCount(vulnerabilities []model.Vulnerability) int {
	count := 0
	for _, vulnerability := range vulnerabilities {
		if vulnerability.ActivelyExploited {
			count++
		}
	}
	return count
}

func (u *convertUI) render(format, output string, count, skipped, exploited int, attested bool) {
	if u == nil || u.progress == nil || !u.progress.Enabled() {
		return
	}
	attestation := "not requested"
	if attested {
		attestation = "signed"
	}
	_ = ui.RenderResults(u.stderr, ui.Dashboard{Summary: ui.SummaryView{
		Decision: "CONVERTED",
		Fields: []ui.Field{
			{Label: "FORMAT", Value: format},
			{Label: "OUTPUT", Value: output},
			{Label: "VULNERABILITIES", Value: fmt.Sprintf("%d", count)},
			{Label: "SKIPPED", Value: fmt.Sprintf("%d", skipped)},
			{Label: "EXPLOITED", Value: fmt.Sprintf("%d", exploited)},
			{Label: "ATTESTATION", Value: attestation},
		},
	}})
}

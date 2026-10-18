// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"fmt"
	"io"
	"strings"

	prov "github.com/had-nu/wardex/v2/pkg/provenance"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type provenanceUI struct {
	progress          *ui.TerminalProgress
	session           ui.SessionView
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func beginProvenanceUI(cmd *cobra.Command, command, detail string) *provenanceUI {
	stderr := cmd.ErrOrStderr()
	session := ui.SessionView{
		Title:  "PROVENANCE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "DETAIL", Value: detail},
		},
	}
	output := cmd.OutOrStdout()
	format := ""
	if command == "attest" {
		format = "cbor"
	}
	progress := ui.NewTerminalProgressForOutput(stderr, output, format)
	progress.Begin(session)
	return &provenanceUI{
		progress:          progress,
		session:           session,
		stderr:            stderr,
		output:            output,
		resultInteractive: !ui.IsMachineFormat(format) && ui.IsTerminal(output) && ui.IsTerminal(stderr),
	}
}

func (u *provenanceUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *provenanceUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *provenanceUI) render(dashboard ui.Dashboard) {
	if u == nil || u.progress == nil || !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func buildProvenanceActionDashboard(command string, fields []ui.Field) ui.Dashboard {
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: strings.ToUpper(command),
			Fields:   fields,
		},
	}
}

func buildProvenanceVerifyDashboard(hash string, result *prov.AnchorResult) ui.Dashboard {
	decision := "NOT_FOUND"
	fields := []ui.Field{{Label: "HASH", Value: hash}}
	if result != nil && result.DryRun {
		decision = "DRY RUN"
		fields = append(fields, ui.Field{Label: "MODE", Value: "no persistence; hash not checked"})
	} else if result != nil && result.Found {
		decision = "FOUND"
		fields = append(fields,
			ui.Field{Label: "BLOCK", Value: fmt.Sprintf("%d", result.BlockIndex)},
			ui.Field{Label: "LABEL", Value: result.Label},
			ui.Field{Label: "STATE ROOT", Value: fmt.Sprintf("%x", result.StateRoot)},
			ui.Field{Label: "PROOF", Value: fmt.Sprintf("%d bytes", len(result.Proof))},
		)
	}
	return ui.Dashboard{Summary: ui.SummaryView{Decision: decision, Fields: fields}}
}

func buildProvenanceStatusDashboard(health *prov.Health) ui.Dashboard {
	if health == nil {
		return ui.Dashboard{Summary: ui.SummaryView{Decision: "UNKNOWN", Fields: []ui.Field{{Label: "DETAIL", Value: "no health response"}}}}
	}
	if health.DryRun {
		return ui.Dashboard{Summary: ui.SummaryView{Decision: "DRY RUN", Fields: []ui.Field{{Label: "MODE", Value: "no persistence; anchor not queried"}}}}
	}
	fields := []ui.Field{
		{Label: "BLOCK HEIGHT", Value: fmt.Sprintf("%d", health.BlockHeight)},
		{Label: "ACTIVE PEERS", Value: fmt.Sprintf("%d", health.ActivePeers)},
		{Label: "PENDING", Value: fmt.Sprintf("%d", health.Pending)},
	}
	return ui.Dashboard{Summary: ui.SummaryView{Decision: "HEALTHY", Fields: fields}}
}

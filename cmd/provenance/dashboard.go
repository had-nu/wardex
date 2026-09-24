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
	progress *ui.TerminalProgress
	session  ui.SessionView
	stderr   io.Writer
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
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(session)
	return &provenanceUI{progress: progress, session: session, stderr: stderr}
}

func (u *provenanceUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *provenanceUI) render(dashboard ui.Dashboard) {
	if u == nil || u.progress == nil || !u.progress.Enabled() {
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
	if result != nil && result.Found {
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
	fields := []ui.Field{}
	if health != nil {
		fields = append(fields,
			ui.Field{Label: "BLOCK HEIGHT", Value: fmt.Sprintf("%d", health.BlockHeight)},
			ui.Field{Label: "ACTIVE PEERS", Value: fmt.Sprintf("%d", health.ActivePeers)},
			ui.Field{Label: "PENDING", Value: fmt.Sprintf("%d", health.Pending)},
		)
	}
	return ui.Dashboard{Summary: ui.SummaryView{Decision: "HEALTHY", Fields: fields}}
}

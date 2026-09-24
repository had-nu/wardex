// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package art14

import (
	"fmt"
	"io"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

const maxArt14Cards = 10

type art14UI struct {
	progress *ui.TerminalProgress
	session  ui.SessionView
	stderr   io.Writer
}

func beginArt14UI(cmd *cobra.Command, command, dir string) *art14UI {
	stderr := cmd.ErrOrStderr()
	session := ui.SessionView{
		Title:  "ARTICLE 14 SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "DIRECTORY", Value: dir},
		},
	}
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(session)
	return &art14UI{progress: progress, session: session, stderr: stderr}
}

func (u *art14UI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{
		Number: number,
		Name:   name,
		Status: status,
		Detail: detail,
	})
}

func (u *art14UI) render(dashboard ui.Dashboard) {
	if u == nil || u.progress == nil || !u.progress.Enabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func buildArt14ListDashboard(artefacts []*model.Art14NotificationArtefact, dir string) ui.Dashboard {
	dashboard := ui.Dashboard{}
	draft, dispatched, overdue := 0, 0, 0
	for _, artefact := range artefacts {
		if strings.HasPrefix(artefact.Status, "dispatched") {
			dispatched++
		} else {
			draft++
		}
		if deadlineOverdue(artefact.EarlyWarning.Deadline, artefact.Status) ||
			deadlineOverdue(artefact.Notification.Deadline, artefact.Status) {
			overdue++
		}
	}

	limit := min(maxArt14Cards, len(artefacts))
	for _, artefact := range artefacts[:limit] {
		dashboard.Findings = append(dashboard.Findings, buildArt14ArtefactView(artefact, ""))
	}

	decision := "REVIEW"
	if len(artefacts) == 0 {
		decision = "EMPTY"
	} else if draft == 0 && overdue == 0 {
		decision = "COMPLETE"
	}
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "DIRECTORY", Value: dir},
			{Label: "ARTEFACTS", Value: fmt.Sprintf("%d", len(artefacts))},
			{Label: "DRAFT", Value: fmt.Sprintf("%d", draft)},
			{Label: "DISPATCHED", Value: fmt.Sprintf("%d", dispatched)},
			{Label: "OVERDUE", Value: fmt.Sprintf("%d", overdue)},
		},
	}
	return dashboard
}

func buildArt14DetailDashboard(artefact *model.Art14NotificationArtefact, action string) ui.Dashboard {
	dashboard := ui.Dashboard{
		Findings: []ui.FindingView{buildArt14ArtefactView(artefact, action)},
	}
	decision := "REVIEW"
	if strings.HasPrefix(artefact.Status, "dispatched") {
		decision = "COMPLETE"
	}
	if action != "" {
		decision = "UPDATED"
	}
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "ARTEFACT", Value: shortID(artefact.ArtefactID)},
			{Label: "STATUS", Value: art14StatusLabel(artefact.Status)},
			{Label: "ACTION", Value: action},
		},
	}
	return dashboard
}

func buildArt14ArtefactView(artefact *model.Art14NotificationArtefact, action string) ui.FindingView {
	severity := "MEDIUM"
	if strings.HasPrefix(artefact.Status, "dispatched") &&
		!deadlineOverdue(artefact.EarlyWarning.Deadline, artefact.Status) &&
		!deadlineOverdue(artefact.Notification.Deadline, artefact.Status) {
		severity = "LOW"
	}
	if deadlineOverdue(artefact.EarlyWarning.Deadline, artefact.Status) ||
		deadlineOverdue(artefact.Notification.Deadline, artefact.Status) {
		severity = "HIGH"
	}

	title := strings.Join(artefact.Notification.CVEIDs, ", ")
	if title == "" {
		title = artefact.ArtefactID
	}
	fields := []ui.Field{
		{Label: "ARTEFACT", Value: shortID(artefact.ArtefactID)},
		{Label: "STATUS", Value: art14StatusLabel(artefact.Status)},
		{Label: "EARLY WARNING", Value: fmtTime(artefact.EarlyWarning.Deadline)},
		{Label: "NOTIFICATION", Value: fmtTime(artefact.Notification.Deadline)},
		{Label: "FINAL REPORT", Value: fmtTime(artefact.FinalReport.Deadline)},
		{Label: "HMAC", Value: shortHMAC(artefact.HMAC)},
	}
	if action != "" {
		fields = append(fields, ui.Field{Label: "LAST ACTION", Value: action})
	}

	return ui.FindingView{
		Kind:     "ARTICLE 14 ARTEFACT",
		Severity: severity,
		Title:    title,
		Fields:   fields,
	}
}

func art14StatusLabel(status string) string {
	switch status {
	case "draft":
		return "DRAFT"
	case "dispatched:early-warning":
		return "DISPATCHED - EW"
	case "dispatched:notification":
		return "DISPATCHED - NOTIFICATION"
	case "dispatched:final-report":
		return "DISPATCHED - FINAL REPORT"
	default:
		return strings.ToUpper(status)
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package policy

import (
	"fmt"
	"io"
	"os"
	"strings"

	policyfiles "github.com/had-nu/wardex/v2/internal/policy"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type policyUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func policyCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginPolicyUI(cmd *cobra.Command, command, path string) *policyUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := policyCommandOutput(cmd)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "POLICY WORKSPACE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "INPUT", Value: path},
		},
	})
	return &policyUI{
		progress:          progress,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *policyUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *policyUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *policyUI) render(dashboard ui.Dashboard) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func policySeverity(status policyfiles.Status) string {
	switch status {
	case policyfiles.StatusCompliant:
		return "LOW"
	case policyfiles.StatusPartial:
		return "MEDIUM"
	case policyfiles.StatusNonCompliant:
		return "HIGH"
	default:
		return "LOW"
	}
}

func policyStatus(status policyfiles.Status) string {
	return strings.ToUpper(string(status))
}

func buildPolicyValidateDashboard(path string, domains []*policyfiles.DomainFile) ui.Dashboard {
	controls := 0
	for _, domain := range domains {
		controls += len(domain.Controls)
	}
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: "VALID",
			Fields: []ui.Field{
				{Label: "FRAMEWORK", Value: path},
				{Label: "DOMAINS", Value: fmt.Sprintf("%d", len(domains))},
				{Label: "CONTROLS", Value: fmt.Sprintf("%d", controls)},
			},
		},
	}
}

func buildPolicyListDashboard(path string, domains []*policyfiles.DomainFile) ui.Dashboard {
	counts := map[policyfiles.Status]int{}
	total := 0
	dashboard := ui.Dashboard{}
	for _, domain := range domains {
		for _, control := range domain.Controls {
			total++
			counts[control.Status]++
			if len(dashboard.Findings) >= 25 {
				continue
			}
			title := control.ID
			if control.Title != "" {
				title = control.Title
			}
			dashboard.Findings = append(dashboard.Findings, ui.FindingView{
				Kind:     "POLICY CONTROL",
				Severity: policySeverity(control.Status),
				Title:    title,
				Fields: []ui.Field{
					{Label: "CONTROL", Value: control.ID},
					{Label: "STATUS", Value: policyStatus(control.Status)},
					{Label: "OWNER", Value: control.Owner},
					{Label: "LAST ASSESSED", Value: control.LastAssessed},
					{Label: "DOMAIN", Value: domain.Domain},
				},
			})
		}
	}
	decision := "REVIEW"
	if counts[policyfiles.StatusNonCompliant] == 0 && counts[policyfiles.StatusPartial] == 0 {
		decision = "COMPLIANT"
	}
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "FRAMEWORK", Value: path},
			{Label: "TOTAL", Value: fmt.Sprintf("%d", total)},
			{Label: "COMPLIANT", Value: fmt.Sprintf("%d", counts[policyfiles.StatusCompliant])},
			{Label: "PARTIAL", Value: fmt.Sprintf("%d", counts[policyfiles.StatusPartial])},
			{Label: "NON-COMPLIANT", Value: fmt.Sprintf("%d", counts[policyfiles.StatusNonCompliant])},
		},
	}
	return dashboard
}

type expiredPolicyException struct {
	ControlID string
	Domain    string
	Expiry    string
	Reason    string
}

func buildPolicyExpiryDashboard(path string, expired []expiredPolicyException) ui.Dashboard {
	decision := "VALID"
	if len(expired) > 0 {
		decision = "EXPIRED"
	}
	dashboard := ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "FRAMEWORK", Value: path},
				{Label: "EXPIRED", Value: fmt.Sprintf("%d", len(expired))},
			},
		},
	}
	for _, exception := range expired {
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "POLICY EXCEPTION",
			Severity: "HIGH",
			Title:    exception.ControlID,
			Fields: []ui.Field{
				{Label: "CONTROL", Value: exception.ControlID},
				{Label: "DOMAIN", Value: exception.Domain},
				{Label: "EXPIRY", Value: exception.Expiry},
				{Label: "REASON RECORDED", Value: boolLabel(exception.Reason != "")},
			},
		})
	}
	return dashboard
}

func boolLabel(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func buildPolicyActionDashboard(command, path, controlID string, updated bool) ui.Dashboard {
	decision := "ADDED"
	if updated {
		decision = "UPDATED"
	}
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: decision,
			Fields: []ui.Field{
				{Label: "COMMAND", Value: strings.ToUpper(command)},
				{Label: "FILE", Value: path},
				{Label: "CONTROL", Value: controlID},
			},
		},
	}
}

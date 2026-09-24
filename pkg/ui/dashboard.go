// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
	"io"
	"strings"
)

// Field is a stable label/value pair used by dashboard cards.
type Field struct {
	Label string
	Value string
}

// SessionView describes the evaluation currently being displayed.
type SessionView struct {
	Title  string
	Status string
	Fields []Field
}

// PhaseView describes one user-visible pipeline phase.
type PhaseView struct {
	Number int
	Name   string
	Status string
	Detail string
}

// FindingView is a renderer-neutral representation of a compliance gap.
type FindingView struct {
	Kind       string
	Severity   string
	Title      string
	Confidence string
	Fields     []Field
}

// SummaryView contains the executive result shown after the details.
type SummaryView struct {
	Decision string
	Fields   []Field
}

// Dashboard is the data-only input to the human terminal renderer.
type Dashboard struct {
	Session  SessionView
	Phases   []PhaseView
	Findings []FindingView
	Summary  SummaryView
}

// RenderDashboard renders a dashboard only to an interactive terminal. It
// returns false for pipes, files and CI so structured output stays clean.
func RenderDashboard(w io.Writer, dashboard Dashboard) bool {
	profile := DetectProfile(w)
	if !profile.Interactive {
		return false
	}
	NewRenderer(w, profile).Dashboard(dashboard)
	return true
}

// RenderResults renders only findings and the executive summary. It is used
// after a live progress reporter has already rendered the session and phases.
func RenderResults(w io.Writer, dashboard Dashboard) bool {
	profile := DetectProfile(w)
	if !profile.Interactive {
		return false
	}
	NewRenderer(w, profile).Results(dashboard)
	return true
}

// Dashboard writes the session, phases, findings and summary in the visual
// order established by the terminal UI reference.
func (r *Renderer) Dashboard(d Dashboard) {
	if d.Session.Title == "" && len(d.Session.Fields) > 0 {
		d.Session.Title = "EVALUATION SESSION"
	}
	if d.Session.Title != "" || len(d.Session.Fields) > 0 {
		r.sessionCard(d.Session)
	}
	r.phaseList(d.Phases)
	for _, finding := range d.Findings {
		r.findingCard(finding)
	}
	if len(d.Summary.Fields) > 0 || d.Summary.Decision != "" {
		r.summaryCard(d.Summary)
	}
}

func (r *Renderer) Results(d Dashboard) {
	fmt.Fprintln(r.w)
	for _, finding := range d.Findings {
		r.findingCard(finding)
	}
	if len(d.Summary.Fields) > 0 || d.Summary.Decision != "" {
		r.summaryCard(d.Summary)
	}
}

func (r *Renderer) sessionCard(session SessionView) {
	title := session.Title
	status := strings.ToUpper(session.Status)
	lines := make([]string, 0, len(session.Fields))
	for _, field := range session.Fields {
		lines = append(lines, r.KeyValue(field.Label, field.Value, 14))
	}
	r.card(title, status, statusKind(status), lines)
}

func (r *Renderer) phaseList(phases []PhaseView) {
	if len(phases) == 0 {
		return
	}
	fmt.Fprintln(r.w)
	for i, phase := range phases {
		if phase.Number <= 0 {
			phase.Number = i + 1
		}
		r.writePhaseLine(phase, true)
	}
	fmt.Fprintln(r.w)
}

func (r *Renderer) writePhaseLine(phase PhaseView, includeDetail bool) {
	number := phase.Number
	if number <= 0 {
		number = 1
	}
	status := strings.ToUpper(phase.Status)
	if status == "" {
		status = "PENDING"
	}
	marker := phaseMarker(status, r.profile.Unicode)
	name := truncate(phase.Name, max(1, r.ContentWidth()-8))
	leftPlain := fmt.Sprintf("%02d %s %s", number, marker, name)
	gap := r.ContentWidth() - VisibleLen(leftPlain) - VisibleLen(status)
	if gap < 1 {
		gap = 1
	}

	left := r.theme.Muted(fmt.Sprintf("%02d", number)) + " " +
		r.theme.Structure(marker) + " " + r.theme.Heading(name)
	fmt.Fprint(r.w, left)
	fmt.Fprint(r.w, strings.Repeat(" ", gap))
	fmt.Fprintln(r.w, r.theme.Status(status, statusKind(status)))

	if includeDetail && phase.Detail != "" {
		prefix := "└─ "
		if !r.profile.Unicode {
			prefix = "\\- "
		}
		detail := truncate(prefix+phase.Detail, r.ContentWidth()-4)
		fmt.Fprintln(r.w, "    "+r.theme.Muted(detail))
	}
}

func (r *Renderer) findingCard(finding FindingView) {
	kind := finding.Kind
	if kind == "" {
		kind = "COMPLIANCE GAP"
	}
	right := ""
	if finding.Confidence != "" {
		separator := "·"
		if !r.profile.Unicode {
			separator = "|"
		}
		right = "CONFIDENCE " + separator + " " + finding.Confidence
	}

	lines := make([]string, 0, len(finding.Fields)+1)
	if finding.Title != "" {
		title := finding.Title
		if finding.Severity != "" {
			title = finding.Severity + "  " + title
		}
		lines = append(lines, r.theme.Status(title, statusKind(finding.Severity)))
	}
	for _, field := range finding.Fields {
		lines = append(lines, r.KeyValue(field.Label, field.Value, 14))
	}
	r.card(kind, right, statusKind(finding.Severity), lines)
}

func (r *Renderer) summaryCard(summary SummaryView) {
	fields := make([]string, 0, len(summary.Fields))
	for _, field := range summary.Fields {
		fields = append(fields, r.KeyValue(field.Label, field.Value, 14))
	}
	right := ""
	if summary.Decision != "" {
		right = strings.ToUpper(summary.Decision)
	}
	r.card("EXECUTIVE SUMMARY", right, statusKind(summary.Decision), fields)
}

func (r *Renderer) card(title, right string, kind StatusKind, lines []string) {
	width := r.ContentWidth()
	left, horizontal, vertical, bottomLeft, bottomRight := r.boxChars()
	corner := rightCornerFor(vertical)
	prefix := left + horizontal + " "
	right = truncate(right, max(0, width/3))
	maxTitle := width - VisibleLen(prefix) - VisibleLen(right) - 1 - 1
	if maxTitle < 1 {
		maxTitle = 1
	}
	title = truncate(title, maxTitle)
	suffix := right
	if suffix != "" {
		suffix += " "
	}
	suffix += corner
	fill := width - VisibleLen(prefix) - VisibleLen(title) - VisibleLen(suffix)
	if fill < 0 {
		fill = 0
	}

	top := r.theme.Structure(prefix) + r.theme.Heading(title) +
		r.theme.Structure(strings.Repeat(horizontal, fill))
	if right != "" {
		top += r.theme.Status(right, kind) + r.theme.Structure(" ")
	}
	top += r.theme.Structure(corner)
	fmt.Fprintln(r.w, top)

	inner := width - 4
	for _, line := range lines {
		line = truncateANSI(line, inner)
		padding := inner - VisibleLen(line)
		if padding < 0 {
			padding = 0
		}
		fmt.Fprint(r.w, r.theme.Structure(vertical+" "))
		fmt.Fprint(r.w, line)
		fmt.Fprint(r.w, strings.Repeat(" ", padding))
		fmt.Fprintln(r.w, r.theme.Structure(" "+vertical))
	}

	fmt.Fprintln(r.w, r.theme.Structure(bottomLeft+strings.Repeat(horizontal, width-2)+bottomRight))
	fmt.Fprintln(r.w)
}

func (r *Renderer) boxChars() (left, horizontal, vertical, bottomLeft, bottomRight string) {
	if r.profile.Unicode {
		return "┌", "─", "│", "└", "┘"
	}
	return "+", "-", "|", "+", "+"
}

func rightCornerFor(vertical string) string {
	if vertical == "│" {
		return "┐"
	}
	return "+"
}

func phaseMarker(status string, unicode bool) string {
	if !unicode {
		switch status {
		case "DONE", "COMPLETE", "COMPLETED":
			return "+"
		case "RUNNING", "ACTIVE":
			return ">"
		case "FAILED", "FAIL", "ERROR":
			return "x"
		case "SKIPPED", "SKIP":
			return "-"
		default:
			return "."
		}
	}

	switch status {
	case "DONE", "COMPLETE", "COMPLETED":
		return "✓"
	case "RUNNING", "ACTIVE":
		return "▶"
	case "FAILED", "FAIL", "ERROR":
		return "✗"
	case "SKIPPED", "SKIP":
		return "−"
	default:
		return "·"
	}
}

func statusKind(value string) StatusKind {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "RUNNING", "ACTIVE", "PENDING":
		return StatusRunning
	case "DONE", "COMPLETE", "COMPLETED", "PASS", "ALLOW", "ALLOWED", "SUCCESS", "READY", "GENERATED", "SEALED", "ADDED", "INITIALISED", "INITIALIZED", "UPDATED", "VALID", "VERIFIED", "COMPUTED", "CONVERTED", "LOADED", "CREATED", "ACKNOWLEDGED", "RECORDED", "CLEAR", "FORWARDING READY":
		return StatusSuccess
	case "WARN", "WARNING", "MEDIUM", "PARTIAL", "REVIEW", "NOT_INITIALIZED", "EMPTY", "NO EVENTS":
		return StatusWarning
	case "FAIL", "FAILED", "ERROR", "BLOCK", "BLOCKED", "HIGH", "DANGER", "REVOKED", "INVALID", "BROKEN", "EXPIRED", "MISMATCH", "DUPLICATE":
		return StatusDanger
	default:
		return StatusNeutral
	}
}

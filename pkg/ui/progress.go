// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"fmt"
	"io"
	"sync"
)

// PhaseEvent is a renderer-neutral progress notification emitted by the
// orchestration layer.
type PhaseEvent struct {
	Number int
	Name   string
	Status string
	Detail string
}

// ProgressReporter receives pipeline lifecycle events. Implementations must
// be safe for the caller's concurrency model; the current pipeline is
// sequential, but the contract does not require that.
type ProgressReporter interface {
	Report(PhaseEvent)
}

// NoopProgressReporter is the default used when a caller does not request
// human-facing progress.
type NoopProgressReporter struct{}

// Report implements ProgressReporter without producing output.
func (NoopProgressReporter) Report(PhaseEvent) {}

// TerminalProgress prints compact phase transitions to an interactive
// terminal. It intentionally prints start and completion events separately;
// this avoids cursor manipulation and remains reliable over SSH, dumb
// terminals and terminal multiplexers.
type TerminalProgress struct {
	mu       sync.Mutex
	w        io.Writer
	renderer *Renderer
	enabled  bool
}

// NewTerminalProgress creates a progress reporter for w. A non-interactive
// writer yields a disabled reporter, allowing the caller to pass it without
// branching.
func NewTerminalProgress(w io.Writer) *TerminalProgress {
	profile := DetectProfile(w)
	if !profile.Interactive {
		return &TerminalProgress{w: w}
	}
	return &TerminalProgress{
		w:        w,
		renderer: NewRenderer(w, profile),
		enabled:  true,
	}
}

// Enabled reports whether the reporter has an interactive destination.
func (p *TerminalProgress) Enabled() bool {
	return p != nil && p.enabled
}

// Begin renders the session card before the first phase starts.
func (p *TerminalProgress) Begin(session SessionView) {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderer.sessionCard(session)
	fmt.Fprintln(p.w)
}

// Report prints one phase transition.
func (p *TerminalProgress) Report(event PhaseEvent) {
	if !p.Enabled() {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderer.writePhaseLine(PhaseView(event), true)
}

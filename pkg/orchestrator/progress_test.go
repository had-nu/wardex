// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/ui"
)

type recordingProgress struct {
	events []ui.PhaseEvent
}

func (r *recordingProgress) Report(event ui.PhaseEvent) {
	r.events = append(r.events, event)
}

func TestEvaluationPipelineReportsProgress(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, dir, "wardex-config.yaml", "{}\n")
	writeFixture(t, dir, "controls.yaml", testControlsYAML)

	progress := &recordingProgress{}
	opts := baseEvalOptions(dir)
	opts.NoSnapshot = true
	opts.OutFile = filepath.Join(dir, "report.md")
	opts.Progress = progress
	opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	opts.Stderr = io.Discard

	if _, err := NewEvaluationPipeline(opts).Run(context.Background(), opts); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(progress.events) < 9 {
		t.Fatalf("expected progress for the pipeline phases, got %d events", len(progress.events))
	}

	seenRunning := false
	seenDone := false
	for _, event := range progress.events {
		if event.Status == "RUNNING" {
			seenRunning = true
		}
		if event.Status == "DONE" {
			seenDone = true
		}
	}
	if !seenRunning || !seenDone {
		t.Fatalf("expected running and done events, got %+v", progress.events)
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package simulate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunSimulateWritesStandaloneHTML(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	if err := runSimulate(cmd, nil); err != nil {
		t.Fatalf("runSimulate failed: %v", err)
	}

	path := filepath.Join(dir, "wardex-simulator.html")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("simulator file was not written: %v", err)
	}
	if !strings.Contains(string(data), "Wardex Risk Simulator") {
		t.Fatalf("generated HTML is missing simulator title")
	}
	if !strings.Contains(stdout.String(), "generated successfully") {
		t.Fatalf("unexpected non-interactive output: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "\033[") {
		t.Fatalf("non-interactive output contains ANSI: %q", stdout.String())
	}
}

func TestBuildSimulatorDashboard(t *testing.T) {
	dashboard := buildSimulatorDashboard("/tmp/wardex-simulator.html", 1234)
	if dashboard.Summary.Decision != "READY" {
		t.Fatalf("unexpected simulator decision: %q", dashboard.Summary.Decision)
	}
	if len(dashboard.Summary.Fields) != 3 {
		t.Fatalf("expected three simulator summary fields, got %d", len(dashboard.Summary.Fields))
	}
}

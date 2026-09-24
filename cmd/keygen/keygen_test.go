// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package keygen

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunKeygenWritesKeypair(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	outPath = filepath.Join(dir, "root.key")
	force = false
	encrypt = false
	passphrase = ""

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := runKeygen(cmd, nil); err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("private key was not written: %v", err)
	}
	if _, err := os.Stat(outPath + ".pub"); err != nil {
		t.Fatalf("public key was not written: %v", err)
	}
	if !strings.Contains(stdout.String(), "Keypair generated") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "\033[") {
		t.Fatalf("non-interactive output contains ANSI: %q", stdout.String())
	}
}

func TestBuildKeygenDashboard(t *testing.T) {
	dashboard := buildKeygenDashboard("/tmp/root.key", nil, true)
	if dashboard.Summary.Decision != "GENERATED" {
		t.Fatalf("unexpected decision: %q", dashboard.Summary.Decision)
	}
	if len(dashboard.Summary.Fields) != 4 {
		t.Fatalf("expected four key summary fields, got %d", len(dashboard.Summary.Fields))
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestEPSSNoScoresUsesConfiguredOutput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("WARDEX_ACCEPT_SECRET", "test-secret-key-123456789012345678901234")

	configFile := filepath.Join(dir, "config.yaml")
	inputFile := filepath.Join(dir, "vulns.yaml")
	if err := os.WriteFile(configFile, []byte("release_gate: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputFile, []byte("vulnerabilities:\n  - cve_id: CVE-2026-0001\n    epss_score: 0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldConfigPath, oldOutput, oldExit := configPathPtr, outputFile, exitFunc
	t.Cleanup(func() { configPathPtr, outputFile, exitFunc = oldConfigPath, oldOutput, oldExit })
	configPathPtr = &configFile
	outputFile = filepath.Join(dir, "signed.yaml")
	var exitCode int
	exitFunc = func(code int) { exitCode = code }

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{Use: "epss"}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	epssCmd.Run(cmd, []string{inputFile})

	if exitCode != 0 {
		t.Fatalf("unexpected exit code %d; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No missing EPSS scores") {
		t.Fatalf("expected configured stdout message, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("non-TTY output contains ANSI: %q", stdout.String())
	}
}

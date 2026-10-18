// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package configseal

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestConfigHashRemainsMachineOriented(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := "config.yaml"
	if err := os.WriteFile(path, []byte("release_gate: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPath, oldAlgorithm := hashConfigPath, hashAlgorithm
	t.Cleanup(func() { hashConfigPath, hashAlgorithm = oldPath, oldAlgorithm })
	hashConfigPath, hashAlgorithm = path, "sha256"

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{Use: "hash"}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := runConfigHash(cmd, nil); err != nil {
		t.Fatalf("runConfigHash failed: %v", err)
	}
	if !strings.HasPrefix(stdout.String(), "sha256:") || strings.Contains(stdout.String(), "WARDEX") {
		t.Fatalf("unexpected machine output: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("machine-oriented hash wrote human stderr: %q", stderr.String())
	}
}

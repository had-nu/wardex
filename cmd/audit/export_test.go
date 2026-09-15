// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package audit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/cmd/audit"
)

func TestExportJSONLCommand(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	genExportLog(t, dir, 4)

	var out, errBuf bytes.Buffer
	audit.AuditCmd.SetOut(&out)
	audit.AuditCmd.SetErr(&errBuf)
	audit.AuditCmd.SetArgs([]string{
		"export", "--audit-log", filepath.Join(dir, "audit.log"),
		"--format", "jsonl", "--limit", "3",
	})
	if err := audit.AuditCmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("foram entregues %d linhas, esperado 3", len(lines))
	}
	for _, l := range lines {
		if l == "" || !strings.HasPrefix(l, "{") {
			t.Errorf("linha não-JSONL: %q", l)
		}
	}
	meta := errBuf.String()
	if !strings.Contains(meta, "x-wardex-has-more=true") {
		t.Errorf("metadata devia ter has-more true:\n%s", meta)
	}
	if !strings.Contains(meta, "x-wardex-next-cursor=") {
		t.Errorf("metadata devia ter next-cursor:\n%s", meta)
	}
}

func TestExportCSVCommand(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	genExportLog(t, dir, 2)

	var out, errBuf bytes.Buffer
	audit.AuditCmd.SetOut(&out)
	audit.AuditCmd.SetErr(&errBuf)
	audit.AuditCmd.SetArgs([]string{
		"export", "--audit-log", filepath.Join(dir, "audit.log"),
		"--format", "csv", "--limit", "2",
	})
	if err := audit.AuditCmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}

	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(rows) != 3 { // header + 2 rows
		t.Fatalf("csv rows = %d, esperado 3 (header+2)", len(rows))
	}
	header := rows[0]
	for _, col := range []string{"ts", "event", "previous_entry_hash", "release_version"} {
		if !strings.Contains(header, col) {
			t.Errorf("header sem coluna %q: %s", col, header)
		}
	}
	if !strings.Contains(errBuf.String(), "x-wardex-has-more=false") {
		t.Errorf("metadata devia ter has-more false:\n%s", errBuf.String())
	}
}

func TestExportTailCommand(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	genExportLog(t, dir, 5)

	var out, errBuf bytes.Buffer
	audit.AuditCmd.SetOut(&out)
	audit.AuditCmd.SetErr(&errBuf)
	audit.AuditCmd.SetArgs([]string{
		"export", "--audit-log", filepath.Join(dir, "audit.log"),
		"--format", "jsonl", "--tail", "--limit", "2",
	})
	if err := audit.AuditCmd.Execute(); err != nil {
		t.Fatalf("export --tail: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Errorf("tail entregou %d linhas, esperado 2", len(lines))
	}
	if !strings.Contains(out.String(), "cfg-004") {
		t.Errorf("tail devia incluir a entrada mais recente (cfg-004):\n%s", out.String())
	}
}

// genExportLog writes a chained JSONL audit log with n entries tagged cfg-000..n-1.
func genExportLog(t *testing.T, dir string, n int) {
	t.Helper()
	logPath := filepath.Join(dir, "audit.log")
	prev := ""
	var b bytes.Buffer
	for i := range n {
		line := fmt.Sprintf(
			`{"ts":"2026-09-01T%02d:00:00Z","event":"gate.evaluated","config_hash":"cfg-%03d","previous_entry_hash":"%s"}`,
			i%24, i, prev,
		)
		b.WriteString(line + "\n")
		h := sha256Sum(line)
		prev = h
	}
	if err := os.WriteFile(logPath, b.Bytes(), 0o600); err != nil {
		t.Fatalf("escrever log: %v", err)
	}
}

func sha256Sum(line string) string {
	h := sha256.Sum256([]byte(line))
	return hex.EncodeToString(h[:])
}

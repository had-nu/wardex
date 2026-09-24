// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package gatecmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acceptaudit "github.com/had-nu/wardex/v2/pkg/accept/audit"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/versionregistry"
)

func sealVersion(t *testing.T, logPath, version, policyRef string) {
	t.Helper()
	t.Chdir(filepath.Dir(logPath))
	if err := acceptaudit.ChainedAuditLog(logPath, model.AuditEntry{
		Timestamp:        time.Now().UTC(),
		Event:            "gate.evaluated",
		ReleaseVersion:   version,
		PolicyRef:        policyRef,
		CplSchemaVersion: 2,
	}); err != nil {
		t.Fatalf("seal %s: %v", version, err)
	}
}

func runCheckWithOutput(logPath, version string) (int, string, string) {
	orig := exitFunc
	var code int
	exitFunc = func(c int) { code = c }
	defer func() { exitFunc = orig }()

	var out, errBuf bytes.Buffer
	GateCmd.SetOut(&out)
	GateCmd.SetErr(&errBuf)
	GateCmd.SetArgs([]string{"check-version", "--audit-log", logPath, "--version", version})
	_ = GateCmd.Execute()
	return code, out.String(), errBuf.String()
}

func runCheck(logPath, version string) (int, string) {
	code, _, stderr := runCheckWithOutput(logPath, version)
	return code, stderr
}

func TestCheckVersionDuplicateExit13(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wardex-gate-audit.log")
	sealVersion(t, logPath, "9.9.9", "iso27001:a.8.1@2026-09")

	code, stderr := runCheck(logPath, "9.9.9")
	if code != exitcodes.DuplicateRelease {
		t.Errorf("exit = %d, esperado %d (stderr: %s)", code, exitcodes.DuplicateRelease, stderr)
	}
}

func TestCheckVersionNonInteractiveKeepsMachineOutput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wardex-gate-audit.log")
	sealVersion(t, logPath, "9.9.9", "policy")

	code, stdout, _ := runCheckWithOutput(logPath, "9.9.9")
	if code != exitcodes.DuplicateRelease {
		t.Fatalf("exit = %d, esperado %d", code, exitcodes.DuplicateRelease)
	}
	if !strings.Contains(stdout, "[DUPLICATE RELEASE]") {
		t.Fatalf("expected legacy result on configured stdout, got %q", stdout)
	}
}

func TestCheckVersionNotSealedExit0(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wardex-gate-audit.log")
	sealVersion(t, logPath, "9.9.9", "policy")

	code, _ := runCheck(logPath, "9.9.8")
	if code != 0 {
		t.Errorf("exit = %d, esperado 0", code)
	}
}

func TestCheckVersionRebuildsStaleIndex(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wardex-gate-audit.log")
	sealVersion(t, logPath, "9.9.9", "policy")

	// Corrupt the derived index: check-version must rebuild from the chain.
	if err := os.WriteFile(versionregistry.IndexPath(logPath), []byte(`garbage`), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stderr := runCheck(logPath, "9.9.9")
	if code != exitcodes.DuplicateRelease {
		t.Errorf("exit = %d, esperado %d (stderr: %s)", code, exitcodes.DuplicateRelease, stderr)
	}

	// The rebuilt index should now be fresh and valid.
	reg, err := versionregistry.Load(logPath)
	if err != nil {
		t.Fatalf("load rebuilt index: %v", err)
	}
	if !reg.Has("9.9.9") {
		t.Error("índice reconstruído deveria conter a versão")
	}
}

func TestCheckVersionSealedAfterIndex(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wardex-gate-audit.log")
	sealVersion(t, logPath, "1.0.0", "policy")

	// Index is fresh for 1.0.0, then a new release seals after it.
	if _, err := versionregistry.New().Rebuild(logPath); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	sealVersion(t, logPath, "2.0.0", "policy")

	// A stale index would miss 2.0.0; check-version must notice and rebuild.
	code, stderr := runCheck(logPath, "2.0.0")
	if code != exitcodes.DuplicateRelease {
		t.Errorf("exit = %d, esperado %d (stderr: %s)", code, exitcodes.DuplicateRelease, stderr)
	}
}

func TestCheckVersionMissingLogExit1(t *testing.T) {
	code, stderr := runCheck(filepath.Join(t.TempDir(), "does-not-exist.log"), "1.0.0")
	if code != exitcodes.GenericError {
		t.Errorf("exit = %d, esperado %d", code, exitcodes.GenericError)
	}
	if stderr == "" {
		t.Error("erro deveria ser impresso")
	}
}

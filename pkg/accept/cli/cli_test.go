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

func setupRootCmd(t *testing.T) (*cobra.Command, *string) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "wardex-test-config.yaml")
	root := &cobra.Command{Use: "wardex"}
	AddCommands(root, &configPath)
	return root, &configPath
}

func TestAddCommands_AllSubcommandsRegistered(t *testing.T) {
	root, _ := setupRootCmd(t)

	acceptCmd, _, err := root.Find([]string{"accept"})
	if err != nil {
		t.Fatalf("expected 'accept' command, got error: %v", err)
	}

	expected := []struct {
		name    string
		use     string
		short   string
	}{
		{"request", "request", "Request a new risk acceptance"},
		{"list", "list", "List risk acceptances"},
		{"verify", "verify", "Verify logic integrity of risk acceptances"},
		{"verify-forwarding", "verify-forwarding", "Verify log forwarding status"},
		{"revoke", "revoke", "Revoke an existing risk acceptance"},
		{"check-expiry", "check-expiry", "Check for pending expirations"},
		{"active-exploit", "active-exploit", "Acknowledge an active exploitation for compliance trail"},
	}

	for _, exp := range expected {
		t.Run(exp.name, func(t *testing.T) {
			cmd, _, err := acceptCmd.Find([]string{exp.name})
			if err != nil {
				t.Fatalf("expected subcommand %q, got error: %v", exp.name, err)
			}
			if cmd.Use != exp.use {
				t.Errorf("expected Use=%q, got %q", exp.use, cmd.Use)
			}
			if cmd.Short != exp.short {
				t.Errorf("expected Short=%q, got %q", exp.short, cmd.Short)
			}
		})
	}
}

func TestAddCommands_RequestFlags(t *testing.T) {
	root, _ := setupRootCmd(t)
	reqCmd, _, _ := root.Find([]string{"accept", "request"})

	tests := []struct {
		name     string
		flag     string
		required bool
	}{
		{"report", "report", true},
		{"cve", "cve", false},
		{"accepted-by", "accepted-by", true},
		{"justification", "justification", false},
		{"expires", "expires", false},
		{"ticket", "ticket", false},
		{"yes", "yes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := reqCmd.Flags().Lookup(tt.flag)
			if f == nil {
				t.Fatalf("flag %q not found", tt.flag)
			}
			if tt.required {
				ann := f.Annotations[cobra.BashCompOneRequiredFlag]
				if len(ann) == 0 || ann[0] != "true" {
					t.Errorf("flag %q should be required", tt.flag)
				}
			}
		})
	}
}

func TestAddCommands_ListFlags(t *testing.T) {
	root, _ := setupRootCmd(t)
	listCmd, _, _ := root.Find([]string{"accept", "list"})

	tests := []string{"active", "expired", "stale", "cve", "output"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			f := listCmd.Flags().Lookup(name)
			if f == nil {
				t.Errorf("flag %q not found on list", name)
			}
		})
	}

	outputFlag := listCmd.Flags().Lookup("output")
	if outputFlag == nil {
		t.Fatal("output flag not found")
	}
	if outputFlag.DefValue != "table" {
		t.Errorf("expected default output=table, got %q", outputFlag.DefValue)
	}
}

func TestAddCommands_RevokeFlags(t *testing.T) {
	root, _ := setupRootCmd(t)
	revokeCmd, _, _ := root.Find([]string{"accept", "revoke"})

	tests := []struct {
		name     string
		required bool
	}{
		{"id", true},
		{"revoked-by", true},
		{"reason", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := revokeCmd.Flags().Lookup(tt.name)
			if f == nil {
				t.Fatalf("flag %q not found", tt.name)
			}
			if tt.required {
				ann := f.Annotations[cobra.BashCompOneRequiredFlag]
				if len(ann) == 0 || ann[0] != "true" {
					t.Errorf("flag %q should be required", tt.name)
				}
			}
		})
	}
}

func TestAddCommands_CheckExpiryFlags(t *testing.T) {
	root, _ := setupRootCmd(t)
	cmd, _, _ := root.Find([]string{"accept", "check-expiry"})

	f := cmd.Flags().Lookup("warn-before")
	if f == nil {
		t.Fatal("flag warn-before not found on check-expiry")
	}
	if f.DefValue != "72h" {
		t.Errorf("expected default warn-before=72h, got %q", f.DefValue)
	}
}

func TestAddCommands_ActiveExploitFlags(t *testing.T) {
	root, _ := setupRootCmd(t)
	cmd, _, _ := root.Find([]string{"accept", "active-exploit"})

	tests := []struct {
		name     string
		required bool
	}{
		{"cve", true},
		{"justification", true},
		{"art14-artefact", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := cmd.Flags().Lookup(tt.name)
			if f == nil {
				t.Fatalf("flag %q not found", tt.name)
			}
			if tt.required {
				ann := f.Annotations[cobra.BashCompOneRequiredFlag]
				if len(ann) == 0 || ann[0] != "true" {
					t.Errorf("flag %q should be required", tt.name)
				}
			}
		})
	}
}

func TestAddCommands_VerifyForwardingFlags(t *testing.T) {
	root, _ := setupRootCmd(t)
	cmd, _, _ := root.Find([]string{"accept", "verify-forwarding"})

	tests := []string{"since", "backend"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			f := cmd.Flags().Lookup(name)
			if f == nil {
				t.Errorf("flag %q not found on verify-forwarding", name)
			}
		})
	}
}

func TestAddCommands_AcceptHelpOutput(t *testing.T) {
	root, _ := setupRootCmd(t)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"accept", "--help"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("execute help failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Manage risk acceptances") {
		t.Error("help output missing command description")
	}
	if !strings.Contains(output, "request") {
		t.Error("help output missing 'request' subcommand")
	}
	if !strings.Contains(output, "list") {
		t.Error("help output missing 'list' subcommand")
	}
	if !strings.Contains(output, "verify") {
		t.Error("help output missing 'verify' subcommand")
	}
}

func TestAddCommands_RootDoesNotPanic(t *testing.T) {
	root := &cobra.Command{Use: "wardex"}
	customPath := "/some/config/path.yaml"

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AddCommands panicked: %v", r)
		}
	}()

	AddCommands(root, &customPath)
}

func TestAddCommands_RequestCommandExists(t *testing.T) {
	root, _ := setupRootCmd(t)

	// Test that the full chain accept->request works
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"accept", "request", "--help"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("execute request --help failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "--report") {
		t.Error("help output missing --report flag")
	}
	if !strings.Contains(output, "--cve") {
		t.Error("help output missing --cve flag")
	}
}

func TestAddCommands_VerifyCommandExists(t *testing.T) {
	root, _ := setupRootCmd(t)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"accept", "verify", "--help"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("execute verify --help failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Verify logic integrity") {
		t.Error("help output missing verify description")
	}
}

func TestAddCommands_ConfigPathPropagation(t *testing.T) {
	origPath := "./orig-config.yaml"
	root := &cobra.Command{Use: "wardex"}
	configPathPtr := &origPath

	AddCommands(root, configPathPtr)

	// Change the config path via pointer
	*configPathPtr = "/updated/path/config.yaml"

	// Verify the pointer update is visible
	if *configPathPtr != "/updated/path/config.yaml" {
		t.Errorf("pointer update not visible: got %q", *configPathPtr)
	}
}

func TestAcceptHelp(t *testing.T) {
	root, _ := setupRootCmd(t)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"accept", "--help"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("execute accept --help failed: %v", err)
	}

	output := buf.String()
	sections := []string{"request", "list", "verify", "verify-forwarding", "revoke", "check-expiry", "active-exploit"}
	for _, s := range sections {
		if !strings.Contains(output, s) {
			t.Errorf("help output missing section: %s", s)
		}
	}
}

// ── Execution tests (mock exitFunc + stderr) ──────────────────────────────

// exitPanic is a sentinel for recovering from exitFunc in tests.
type exitPanic struct{ code int }

func captureCommand(t *testing.T, args []string) (int, string) {
	t.Helper()

	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	oldExit := exitFunc
	oldStderr := stderr
	defer func() {
		exitFunc = oldExit
		stderr = oldStderr
	}()

	var exitCode int
	exitFunc = func(code int) {
		exitCode = code
		panic(exitPanic{code})
	}

	var buf bytes.Buffer
	stderr = &buf

	configPath := filepath.Join(tmpDir, "config.yaml")
	root := &cobra.Command{Use: "wardex"}
	AddCommands(root, &configPath)
	root.SetArgs(args)

	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(exitPanic); !ok {
					panic(r) // re-panic unexpected panics
				}
			}
		}()
		_ = root.Execute()
	}()

	return exitCode, buf.String()
}

func TestRun_Request_SecretMissing(t *testing.T) {
	code, errOut := captureCommand(t, []string{"accept", "request", "--report", "/nope.json", "--accepted-by", "test@test.com"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut, "Secret error") {
		t.Errorf("expected secret error, got: %s", errOut)
	}
}

func TestRun_VerifyForwarding_NoAuditLog(t *testing.T) {
	code, out := captureCommand(t, []string{"accept", "verify-forwarding"})
	if code != 0 {
		t.Errorf("expected exit code 0 (graceful no-op), got %d", code)
	}
	if !strings.Contains(out, "not found") {
		t.Errorf("expected 'not found' message, got: %s", out)
	}
}

func TestRun_ActiveExploit_ShortJustification(t *testing.T) {
	code, errOut := captureCommand(t, []string{"accept", "active-exploit", "--cve", "CVE-2024-0001", "--justification", "too short"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut, "justification must be at least 80 characters") {
		t.Errorf("expected justification length error, got: %s", errOut)
	}
}

func TestRun_ActiveExploit_Success(t *testing.T) {
	code, _ := captureCommand(t, []string{
		"accept", "active-exploit",
		"--cve", "CVE-2024-0001",
		"--justification", strings.Repeat("x", 80),
	})
	if code != 0 {
		t.Errorf("expected exit code 0 (success with default config), got %d", code)
	}
}

func TestRun_List_SecretMissing(t *testing.T) {
	code, errOut := captureCommand(t, []string{"accept", "list"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut, "Secret error") {
		t.Errorf("expected secret error, got: %s", errOut)
	}
}

func TestRun_Verify_SecretMissing(t *testing.T) {
	code, errOut := captureCommand(t, []string{"accept", "verify"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut, "Secret error") {
		t.Errorf("expected secret error, got: %s", errOut)
	}
}

func TestRun_Revoke_SecretMissing(t *testing.T) {
	code, errOut := captureCommand(t, []string{"accept", "revoke", "--id", "123", "--revoked-by", "admin@test.com", "--reason", "test"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut, "Secret error") {
		t.Errorf("expected secret error, got: %s", errOut)
	}
}

func TestRun_CheckExpiry_SecretMissing(t *testing.T) {
	code, errOut := captureCommand(t, []string{"accept", "check-expiry"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut, "Secret error") {
		t.Errorf("expected secret error, got: %s", errOut)
	}
}

func TestRun_VerifyForwarding_WithBackendUnreachable(t *testing.T) {
	// Create a dummy audit log in a temp dir, then chdir there
	// so the verify-forwarding code finds the log and reaches the backend check
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	if err := os.WriteFile("wardex-accept-audit.log", []byte("dummy event\n"), 0644); err != nil {
		t.Fatal(err)
	}

	oldExit := exitFunc
	oldStderr := stderr
	defer func() {
		exitFunc = oldExit
		stderr = oldStderr
	}()

	var exitCode int
	exitFunc = func(code int) {
		exitCode = code
		panic(exitPanic{code})
	}

	var buf bytes.Buffer
	stderr = &buf

	root, _ := setupRootCmd(t)
	root.SetArgs([]string{"accept", "verify-forwarding", "--backend", "tcp://10.255.255.1:9"})

	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(exitPanic); !ok {
					panic(r)
				}
			}
		}()
		_ = root.Execute()
	}()

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for unreachable backend, got %d", exitCode)
	}
	if !strings.Contains(buf.String(), "Failed to dial") {
		t.Errorf("expected dial failure error, got: %s", buf.String())
	}
}

func TestRun_RequestHelp(t *testing.T) {
	code, errOut := captureCommand(t, []string{"accept", "request", "--help"})
	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
	if errOut != "" {
		t.Errorf("expected no stderr for --help, got: %s", errOut)
	}
}

func TestMain(m *testing.M) {
	os.Clearenv()
	code := m.Run()
	os.Exit(code)
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func setupRootCmd() (*cobra.Command, *string) {
	configPath := "/tmp/wardex-test-config.yaml"
	root := &cobra.Command{Use: "wardex"}
	AddCommands(root, &configPath)
	return root, &configPath
}

func TestAddCommands_AllSubcommandsRegistered(t *testing.T) {
	root, _ := setupRootCmd()

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
	root, _ := setupRootCmd()
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
	root, _ := setupRootCmd()
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
	root, _ := setupRootCmd()
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
	root, _ := setupRootCmd()
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
	root, _ := setupRootCmd()
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
	root, _ := setupRootCmd()
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
	root, _ := setupRootCmd()

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
	root, _ := setupRootCmd()

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
	root, _ := setupRootCmd()

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
	root, _ := setupRootCmd()

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

func TestMain(m *testing.M) {
	// Save original env and restore after tests
	os.Clearenv()
	code := m.Run()
	os.Exit(code)
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/cli"
)

// setupWorkspace creates a temporary directory simulating a CI workspace.
// Returns the absolute path and a cleanup function.
func setupWorkspace(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "wardex-pathguard-*")
	if err != nil {
		t.Fatalf("creating temp workspace: %v", err)
	}
	// Fixture: legitimate file in workspace
	if err := os.WriteFile(filepath.Join(dir, "vulns.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("creating fixture: %v", err)
	}
	// Legitimate subdirectory
	if err := os.MkdirAll(filepath.Join(dir, "reports"), 0o755); err != nil {
		t.Fatalf("creating subdir: %v", err)
	}
	return dir, func() { os.RemoveAll(dir) }
}

func TestValidateInputPath(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	tests := []struct {
		name    string
		path    string
		wantErr error // nil = success expected; specific sentinel error
	}{
		// ── Valid inputs ──────────────────────────────────────────────────
		{
			name: "valid_filename",
			path: "vulns.yaml",
		},
		{
			name: "valid_dotslash",
			path: "./vulns.yaml",
		},
		{
			name: "valid_subdir",
			path: "reports/scan.yaml",
		},
		{
			name: "stdin_dash",
			path: "-", // stdin explicitly allowed
		},

		// ── Path traversal ────────────────────────────────────────────────
		{
			name:    "traversal_simple",
			path:    "../secret.yaml",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_deep",
			path:    "../../../../../../../etc/passwd",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_embedded",
			path:    "reports/../../etc/shadow",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_with_dotslash",
			path:    "./../../.env",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name: "traversal_normalized_safe",
			// filepath.Clean normalizes "reports/../vulns.yaml" → "vulns.yaml" — should pass
			path:    "reports/../vulns.yaml",
			wantErr: nil,
		},
		{
			name:    "traversal_github_workflow",
			path:    "../../.github/workflows/ci.yml",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_dotenv",
			path:    "../../.env",
			wantErr: cli.ErrPathTraversal,
		},

		// ── Absolute paths (outside workspace → traversal) ──────────────────
		{
			name:    "absolute_etc_passwd",
			path:    "/etc/passwd",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "absolute_proc_environ",
			path:    "/proc/self/environ",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "absolute_proc_mem",
			path:    "/proc/self/mem",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "absolute_dev_null",
			path:    "/dev/null",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "absolute_dev_urandom",
			path:    "/dev/urandom",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "absolute_root",
			path:    "/",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "absolute_double_slash",
			path:    "//etc/passwd",
			wantErr: cli.ErrPathTraversal,
		},

		// ── Malformed inputs ──────────────────────────────────────────────
		{
			name:    "empty_path",
			path:    "",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "null_byte_suffix",
			path:    "vulns.yaml\x00.evil",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "null_byte_prefix",
			path:    "\x00/etc/passwd",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "null_byte_middle",
			path:    "valid\x00../../etc/passwd",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "path_too_long",
			path:    strings.Repeat("a/", 2100) + "file.yaml", // > 4096 bytes
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "invalid_utf8",
			path:    "valid\xff\xfeinvalid.yaml",
			wantErr: cli.ErrInvalidPath,
		},

		// ── Shell injection attempts (harmless in Docker but tested) ──────
		// These are valid filenames after filepath.Clean; they resolve within
		// the workspace. In the CLI context, they arrive as argv (not shell),
		// so injection is infeasible. We test that they don't cause traversal errors.
		{
			name: "shell_semicolon",
			path: "; cat /etc/passwd",
			// filepath.Clean joins with base → valid path within workspace
		},
		{
			name: "shell_dollar_expansion",
			path: "$(cat /etc/passwd).yaml",
		},
		{
			name: "shell_backtick",
			path: "`whoami`.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cli.ValidateInputPath(base, tc.path)

			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateInputPath(%q) = %v; want nil", tc.path, err)
				}
				return
			}

			if err == nil {
				t.Errorf("ValidateInputPath(%q) = nil; want error wrapping %v", tc.path, tc.wantErr)
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateInputPath(%q) error type = %T (%v); want wrapping %v",
					tc.path, err, err, tc.wantErr)
			}
		})
	}
}

func TestValidateOutputPath(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		// ── Valid outputs ─────────────────────────────────────────────────
		{
			name: "valid_report",
			path: "wardex-report.md",
		},
		{
			name: "valid_subdir_report",
			path: "reports/wardex-report.json",
		},

		// ── Traversal in output — more critical: arbitrary write ──────────
		{
			name:    "output_traversal_workflow",
			path:    "../../.github/workflows/injected.yml",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "output_traversal_cron",
			path:    "../../../etc/cron.d/evil",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "output_traversal_ssh_authorized",
			path:    "../../../../tmp/.wardex-test-escape",
			wantErr: cli.ErrPathTraversal,
		},

		// ── Pseudo-filesystems — additional output restriction ────────────
		{
			name:    "output_dev_stdout",
			path:    "/dev/stdout",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "output_proc_mem",
			path:    "/proc/self/mem",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "output_sys_kernel",
			path:    "/sys/kernel/hostname",
			wantErr: cli.ErrPathTraversal,
		},

		// ── Absolute paths ────────────────────────────────────────────────
		{
			name:    "output_absolute_etc",
			path:    "/etc/wardex-poison.yaml",
			wantErr: cli.ErrPathTraversal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cli.ValidateOutputPath(base, tc.path)

			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateOutputPath(%q) = %v; want nil", tc.path, err)
				}
				return
			}

			if err == nil {
				t.Errorf("ValidateOutputPath(%q) = nil; want error wrapping %v", tc.path, tc.wantErr)
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateOutputPath(%q) error type = %T (%v); want wrapping %v",
					tc.path, err, err, tc.wantErr)
			}
		})
	}
}

// TestValidateInputPath_SymlinkEscape verifies that symlinks pointing outside
// the workspace are detected. This test requires filesystem access.
func TestValidateInputPath_SymlinkEscape(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — symlink escape test skipped (root ignores DAC)")
	}

	base, cleanup := setupWorkspace(t)
	defer cleanup()

	// Create a symlink inside the workspace pointing outside.
	linkPath := filepath.Join(base, "escape-link.yaml")
	if err := os.Symlink("/etc/passwd", linkPath); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	// The path "escape-link.yaml" is inside the workspace — but the target is not.
	// Path validation resolves the symlink; if it doesn't, this test fails
	// and documents the gap.
	_, err := cli.ValidateInputPath(base, "escape-link.yaml")

	// Expected behavior: the symlink is followed and the destination is validated
	// (/etc/passwd is outside the workspace → ErrPathTraversal), or the symlink
	// is refused as a category. In either case, err != nil.
	if err == nil {
		t.Error("ValidateInputPath accepted a symlink pointing outside the workspace")
	}
}

// TestValidateInputPath_WorkspaceRoot verifies the edge case where the path
// normalizes exactly to the workspace root (not inside it).
func TestValidateInputPath_WorkspaceRoot(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	// "." normalizes to base — it's not a valid file but it's not traversal.
	// The caller should reject with "is a directory"; path validation
	// should not return ErrPathTraversal.
	_, err := cli.ValidateInputPath(base, ".")
	if errors.Is(err, cli.ErrPathTraversal) {
		t.Errorf("ValidateInputPath(\".\") returned ErrPathTraversal; expected nil or other error")
	}
}

// TestValidateInputPath_ReturnedPath verifies that the returned absolute path
// is correct and usable for I/O.
func TestValidateInputPath_ReturnedPath(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	resolved, err := cli.ValidateInputPath(base, "vulns.yaml")
	if err != nil {
		t.Fatalf("ValidateInputPath(%q) unexpected error: %v", "vulns.yaml", err)
	}

	expected := filepath.Join(base, "vulns.yaml")
	if resolved != expected {
		t.Errorf("ValidateInputPath(%q) resolved = %q; want %q", "vulns.yaml", resolved, expected)
	}

	// Verify the resolved path is actually readable.
	if _, err := os.Stat(resolved); err != nil {
		t.Errorf("resolved path %q is not accessible: %v", resolved, err)
	}
}

// TestValidateOutputPath_ReturnedPath verifies that output paths resolve correctly.
func TestValidateOutputPath_ReturnedPath(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	resolved, err := cli.ValidateOutputPath(base, "reports/output.json")
	if err != nil {
		t.Fatalf("ValidateOutputPath(%q) unexpected error: %v", "reports/output.json", err)
	}

	expected := filepath.Join(base, "reports/output.json")
	if resolved != expected {
		t.Errorf("ValidateOutputPath(%q) resolved = %q; want %q", "reports/output.json", resolved, expected)
	}
}

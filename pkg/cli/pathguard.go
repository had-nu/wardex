// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package cli provides path validation guards for CLI inputs and outputs.
// ValidateInputPath and ValidateOutputPath confine file access to the workspace
// directory, preventing path traversal, symlink escapes, and malformed paths.
package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ErrPathTraversal is returned when a path resolves outside the base directory.
var ErrPathTraversal = errors.New("path traversal detected")

// ErrAbsolutePath is returned when an absolute path is rejected in a context
// that requires relative paths to the workspace.
var ErrAbsolutePath = errors.New("absolute path not permitted")

// ErrInvalidPath groups errors for malformed inputs (null bytes, invalid UTF-8,
// paths exceeding the maximum length).
var ErrInvalidPath = errors.New("invalid path")

const (
	maxPathLen = 4096 // POSIX maximum path length
)

// ValidateInputPath validates a file input path (--evidence, --config).
// base is the working directory; path is the user-provided value.
//
// Rules:
//   - absolute paths outside the base are rejected
//   - paths escaping base after resolution are rejected
//   - null bytes are rejected (explicit error before any syscall)
//   - invalid UTF-8 sequences are rejected
//   - paths exceeding maxPathLen are rejected
//   - symlinks resolving outside the workspace are rejected
//
// stdin ("-") is accepted and must be handled by the caller.
// Returns the resolved absolute path on success.
func ValidateInputPath(base, path string) (string, error) {
	if path == "-" {
		return "-", nil // stdin explicitly allowed
	}
	return validatePath(base, path, false)
}

// ValidateOutputPath validates a file output path (--out-file).
// Applies the same rules as ValidateInputPath but additionally rejects
// paths targeting /dev/, /proc/, and /sys/ even when relative to the workspace.
// Returns the resolved absolute path on success.
func ValidateOutputPath(base, path string) (string, error) {
	resolved, err := validatePath(base, path, true)
	if err != nil {
		return "", err
	}
	// Additional output restrictions: protect pseudo-filesystems.
	for _, prefix := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(resolved, prefix) {
			return "", fmt.Errorf("%w: output to %s is not permitted", ErrAbsolutePath, prefix)
		}
	}
	return resolved, nil
}

// SafePath combines os.Getwd() + ValidateInputPath into a single call.
// This eliminates the repeated 2-line boilerplate found across the codebase.
func SafePath(relativePath string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	return ValidateInputPath(cwd, relativePath)
}

// SafeOutputPath combines os.Getwd() + ValidateOutputPath into a single call.
func SafeOutputPath(relativePath string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	return ValidateOutputPath(cwd, relativePath)
}

func validatePath(base, path string, isOutput bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: path must not be empty", ErrInvalidPath)
	}
	if len(path) > maxPathLen {
		return "", fmt.Errorf("%w: path exceeds %d bytes", ErrInvalidPath, maxPathLen)
	}
	// Null bytes: Go strings can contain \x00; the kernel rejects them,
	// but we want an explicit error before any I/O.
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("%w: null byte in path", ErrInvalidPath)
	}
	// Valid UTF-8. Paths with invalid bytes can confuse log parsers.
	if !utf8.ValidString(path) {
		return "", fmt.Errorf("%w: invalid UTF-8 sequence", ErrInvalidPath)
	}

	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolving workspace: %w", err)
	}

	// For absolute paths, check containment directly without joining.
	// For relative paths, join with base first.
	var clean string
	if filepath.IsAbs(path) {
		clean = filepath.Clean(path)
	} else {
		clean = filepath.Clean(filepath.Join(base, path))
	}

	// Resolve symlinks before the prefix check to prevent symlink escapes.
	// If the file does not yet exist (output path), accept the syntactic path.
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("resolving symlinks: %w", err)
		}
		resolved = clean
	}

	if !strings.HasPrefix(resolved, absBase+string(os.PathSeparator)) && resolved != absBase {
		return "", fmt.Errorf("%w: %q resolves outside workspace", ErrPathTraversal, path)
	}
	return resolved, nil
}

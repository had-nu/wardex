// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package atomicwrite provides safe atomic file writes using write-to-temp + rename.
// This prevents partial writes from corrupting files on crash or power loss.
// Uses O_EXCL to prevent symlink/pre-existing file attacks.
package atomicwrite

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write atomically writes data to the file at path by writing to a temporary
// file first (using O_EXCL to prevent races), then renaming.
// The temp file is created in the same directory as the target to ensure
// rename is atomic (same filesystem). The parent directory is fsynced
// after rename for durability.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)

	// Create temp file in same directory with O_EXCL to prevent symlink/pre-existing attacks
	f, err := os.CreateTemp(dir, ".wardex-atomic-*")
	if err != nil {
		return fmt.Errorf("atomic write: create temp: %w", err)
	}
	tmpPath := f.Name()

	// Write data
	if _, err := f.Write(data); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic write: write data: %w", err)
	}

	// Ensure data is on disk before rename
	if err := f.Sync(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic write: sync data: %w", err)
	}

	// Set permissions before rename
	if err := f.Chmod(0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic write: chmod: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic write: close: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic write: rename: %w", err)
	}

	// Sync parent directory for durability (rename is not guaranteed durable on all fs)
	dirF, err := os.Open(dir) // #nosec G304 - dir is the parent directory of target path, validated by caller
	if err != nil {
		return fmt.Errorf("atomic write: open dir for sync: %w", err)
	}
	if err := dirF.Sync(); err != nil {
		_ = dirF.Close()
		return fmt.Errorf("atomic write: sync dir: %w", err)
	}
	_ = dirF.Close()

	return nil
}

// WriteWithContext is like Write but respects context cancellation.
func WriteWithContext(ctx interface {
	Done() <-chan struct{}
	Err() error
}, path string, data []byte) error {
	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, ".wardex-atomic-*")
	if err != nil {
		return fmt.Errorf("atomic write: create temp: %w", err)
	}
	tmpPath := f.Name()

	// Use a done channel to handle cleanup on cancellation
	done := make(chan error, 1)
	go func() {
		defer close(done)
		if _, err := f.Write(data); err != nil {
			done <- fmt.Errorf("atomic write: write data: %w", err)
			return
		}
		if err := f.Sync(); err != nil {
			done <- fmt.Errorf("atomic write: sync data: %w", err)
			return
		}
		if err := f.Chmod(0o600); err != nil {
			done <- fmt.Errorf("atomic write: chmod: %w", err)
			return
		}
		if err := f.Close(); err != nil {
			done <- fmt.Errorf("atomic write: close: %w", err)
			return
		}
		if err := os.Rename(tmpPath, path); err != nil {
			done <- fmt.Errorf("atomic write: rename: %w", err)
			return
		}
		dirF, err := os.Open(filepath.Dir(path)) // #nosec G304 - dir is parent of target path, validated by caller
		if err != nil {
			done <- fmt.Errorf("atomic write: open dir for sync: %w", err)
			return
		}
		if err := dirF.Sync(); err != nil {
			_ = dirF.Close()
			done <- fmt.Errorf("atomic write: sync dir: %w", err)
			return
		}
		_ = dirF.Close()
		done <- nil
	}()

	select {
	case <-ctx.Done():
		_ = os.Remove(tmpPath)
		_ = f.Close()
		return ctx.Err()
	case err := <-done:
		return err
	}
}
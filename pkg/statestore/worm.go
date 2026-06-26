// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package statestore

import (
	"os"
	"path/filepath"
)

// LockFile sets the immutable bit (Linux/macOS) or marks as read-only (Windows).
func LockFile(path string) error {
	return lockFile(path)
}

// IsLocked checks if a file has the immutable bit set (Linux/macOS) or is read-only (Windows).
func IsLocked(path string) (bool, error) {
	return isLocked(path)
}

// UnlockFile clears the immutable bit (Linux/macOS) or read-only flag (Windows).
func UnlockFile(path string) error {
	return unlockFile(path)
}

// LockDir locks all files in a directory recursively.
func LockDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return LockFile(path)
	})
}

// UnlockDir unlocks all files in a directory recursively.
func UnlockDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return UnlockFile(path)
	})
}

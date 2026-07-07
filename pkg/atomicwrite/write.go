// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package atomicwrite provides safe atomic file writes using write-to-temp + rename.
// This prevents partial writes from corrupting files on crash or power loss.
package atomicwrite

import (
	"fmt"
	"os"
)

// Write atomically writes data to the file at path by writing to a temporary
// file first, then renaming. The temp file is cleaned up on rename failure.
func Write(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("atomic write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/atomicwrite"
)

// SafeReadFile reads a file after validating its path with SafePath.
// It centralises the #nosec G304 annotation so the path validation lives in a
// single auditable location instead of being repeated at every call site.
func SafeReadFile(path string) ([]byte, error) {
	safePath, err := SafePath(path)
	if err != nil {
		return nil, fmt.Errorf("safe read: %w", err)
	}
	return os.ReadFile(safePath) // #nosec G304 -- validated by SafePath
}

// SafeWriteFile atomically writes data to a file after validating its path with
// SafeOutputPath. The write itself is performed via atomicwrite to prevent
// partial writes on crash or power loss.
func SafeWriteFile(path string, data []byte) error {
	safePath, err := SafeOutputPath(path)
	if err != nil {
		return fmt.Errorf("safe write: %w", err)
	}
	return atomicwrite.Write(safePath, data)
}

// ReadFile reads a file whose path is managed by the caller rather than derived
// from raw CLI input. It centralises the #nosec G304 annotation for internal
// reads (state stores rooted at absolute directories, keyring files, archived
// configs) where cwd-confinement validation is not applicable.
//
// Callers MUST guarantee the path is constructed from trusted state or was
// validated before reaching this function.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- caller-managed trusted path
}

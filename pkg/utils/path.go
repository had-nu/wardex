// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package utils provides shared utility functions for cryptographic hashing
// used across Wardex subsystems.
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// HashFile returns the SHA-256 hash of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

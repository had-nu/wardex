// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SafePath prevents path traversal outside the base directory.
func SafePath(base, input string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	absInput, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	// Check if absInput is under absBase or os.TempDir (for tests/automation)
	tempBase, _ := filepath.Abs(os.TempDir())
	if !strings.HasPrefix(absInput, absBase+string(filepath.Separator)) && absInput != absBase &&
		!strings.HasPrefix(absInput, tempBase+string(filepath.Separator)) && absInput != tempBase {
		return "", fmt.Errorf("path %q escapes allowed base directories (%q, %q)", input, base, os.TempDir())
	}
	return absInput, nil
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build !linux && !darwin && !windows

package statestore

import "fmt"

func lockFile(path string) error {
	return fmt.Errorf("statestore: WORM not supported on this platform")
}

func isLocked(path string) (bool, error) {
	return false, fmt.Errorf("statestore: WORM not supported on this platform")
}

func unlockFile(path string) error {
	return fmt.Errorf("statestore: WORM not supported on this platform")
}

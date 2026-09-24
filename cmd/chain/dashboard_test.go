// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package chain

import "testing"

func TestChainUIDashboardContract(t *testing.T) {
	// The chain UI is intentionally small; this test keeps the public command
	// wiring covered while the end-to-end chain tests exercise the filesystem.
	if SealCmd.Use != "seal" {
		t.Fatalf("unexpected chain command: %q", SealCmd.Use)
	}
}

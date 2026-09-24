// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package hmac

import "testing"

func TestHMACUIUsesSignatureSummary(t *testing.T) {
	if SignCmd.Use != "sign" {
		t.Fatalf("unexpected HMAC command: %q", SignCmd.Use)
	}
}

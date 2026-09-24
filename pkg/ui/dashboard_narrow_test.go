// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestRendererDashboardFitsNarrowTerminal(t *testing.T) {
	var out bytes.Buffer
	r := NewRenderer(&out, Profile{
		Interactive: true,
		ColorDepth:  ColorNone,
		Unicode:     false,
		Width:       32,
	})
	r.Dashboard(testDashboard())

	for _, line := range strings.Split(out.String(), "\n") {
		if VisibleLen(line) > r.ContentWidth() {
			t.Fatalf("line exceeds narrow content width (%d > %d): %q", VisibleLen(line), r.ContentWidth(), line)
		}
	}
}

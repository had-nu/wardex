// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package configseal

import "testing"

func TestBuildConfigSealDashboard(t *testing.T) {
	dashboard := buildConfigSealDashboard("draft.yaml", "sealed.wexstate", "trust.yaml")
	if dashboard.Summary.Decision != "SEALED" {
		t.Fatalf("unexpected seal decision: %q", dashboard.Summary.Decision)
	}
	if len(dashboard.Summary.Fields) != 4 {
		t.Fatalf("expected four seal summary fields, got %d", len(dashboard.Summary.Fields))
	}
}

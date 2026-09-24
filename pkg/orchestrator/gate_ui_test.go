// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
)

func TestRenderGateTableDoesNotEmitANSIForBuffer(t *testing.T) {
	var out bytes.Buffer
	report := model.GateReport{
		OverallDecision:   model.DecisionAllow,
		GateMaturityLevel: 2,
		Decisions: []model.ReleaseDecision{{
			Vulnerability: model.Vulnerability{CVEID: "CVE-1", Component: "demo"},
			ReleaseRisk:   0.1,
			Decision:      model.DecisionAllow,
		}},
	}

	renderGateTable(&out, report, 0.8, 0.3)
	if strings.Contains(out.String(), "\033[") {
		t.Fatalf("non-terminal gate table contains ANSI: %q", out.String())
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package sdk_test

import (
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/sdk"
)

func TestSDK_Analyze(t *testing.T) {
	controls := []model.ExistingControl{
		{ID: "C1", Name: "Access Control", Maturity: 3, Domains: []string{"access_control"}},
	}

	result, err := sdk.Analyze(controls, "iso27001")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result.Summary.TotalControls == 0 {
		t.Error("expected controls in summary")
	}
}

func TestSDK_LoadFramework(t *testing.T) {
	controls := sdk.LoadFramework("iso27001")
	if len(controls) == 0 {
		t.Error("expected ISO27001 controls")
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"testing"

	prov "github.com/had-nu/wardex/v2/pkg/provenance"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

func TestBuildProvenanceVerifyDashboard(t *testing.T) {
	found := buildProvenanceVerifyDashboard("abcd", &prov.AnchorResult{
		Found:      true,
		BlockIndex: 12,
		Label:      "release",
		StateRoot:  []byte{0x01},
		Proof:      []byte{0x02, 0x03},
	})
	if found.Summary.Decision != "FOUND" {
		t.Fatalf("unexpected found decision: %q", found.Summary.Decision)
	}
	notFound := buildProvenanceVerifyDashboard("abcd", &prov.AnchorResult{})
	if notFound.Summary.Decision != "NOT_FOUND" {
		t.Fatalf("unexpected not-found decision: %q", notFound.Summary.Decision)
	}
}

func TestBuildProvenanceStatusDashboard(t *testing.T) {
	dashboard := buildProvenanceStatusDashboard(&prov.Health{BlockHeight: 42, ActivePeers: 2, Pending: 1})
	if dashboard.Summary.Decision != "HEALTHY" || len(dashboard.Summary.Fields) != 3 {
		t.Fatalf("unexpected status dashboard: %+v", dashboard)
	}
}

func TestBuildProvenanceActionDashboard(t *testing.T) {
	dashboard := buildProvenanceActionDashboard("SUBMITTED", []ui.Field{{Label: "HASH", Value: "abcd"}})
	if dashboard.Summary.Decision != "SUBMITTED" || len(dashboard.Summary.Fields) != 1 {
		t.Fatalf("unexpected action dashboard: %+v", dashboard)
	}
}

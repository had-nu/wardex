// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trustcmd

import (
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
)

func testTrustStore() *trust.TrustStore {
	return &trust.TrustStore{
		Keys: []trust.KeyEntry{
			{ID: "admin-01", Actor: "admin@example.test", Name: "Admin", Role: trust.RoleAdmin, AddedAt: time.Now().UTC()},
			{ID: "analyst-01", Actor: "analyst@example.test", Name: "Analyst", Role: trust.RoleAnalyst, AddedAt: time.Now().UTC()},
		},
		Revocations: []trust.Revocation{{KeyID: "analyst-01"}},
	}
}

func TestBuildTrustListDashboard(t *testing.T) {
	dashboard := buildTrustListDashboard(testTrustStore(), "wardex-trust.yaml")
	if len(dashboard.Findings) != 2 {
		t.Fatalf("expected two key cards, got %d", len(dashboard.Findings))
	}
	if dashboard.Findings[1].Severity != "HIGH" {
		t.Fatalf("revoked key should be high severity: %+v", dashboard.Findings[1])
	}
	if dashboard.Summary.Decision != "REVIEW" {
		t.Fatalf("expected review decision, got %q", dashboard.Summary.Decision)
	}
}

func TestBuildTrustDetailDashboard(t *testing.T) {
	entry := testTrustStore().Keys[0]
	dashboard := buildTrustDetailDashboard(entry, "active", "wardex-trust.yaml")
	if len(dashboard.Findings) != 1 || dashboard.Summary.Decision != "READY" {
		t.Fatalf("unexpected trust detail dashboard: %+v", dashboard)
	}
}

func TestBuildTrustActionDashboard(t *testing.T) {
	dashboard := buildTrustActionDashboard("ADDED", "trust.yaml", []ui.Field{{Label: "ACTOR", Value: "admin@example.test"}})
	if dashboard.Summary.Decision != "ADDED" || len(dashboard.Summary.Fields) != 2 {
		t.Fatalf("unexpected trust action dashboard: %+v", dashboard)
	}
}

func TestBuildTrustVerifyDashboard(t *testing.T) {
	dashboard := buildTrustVerifyDashboard("trust.yaml", "admin-01", 2, 1, 1, true)
	if dashboard.Summary.Decision != "VALID" || len(dashboard.Findings) != 1 {
		t.Fatalf("unexpected trust verify dashboard: %+v", dashboard)
	}
}

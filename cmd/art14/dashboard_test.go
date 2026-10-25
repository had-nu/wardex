// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package art14

import (
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v3/pkg/model"
)

func TestBuildArt14ListDashboardSummarizesLifecycle(t *testing.T) {
	now := time.Now().UTC()
	artefacts := []*model.Art14NotificationArtefact{
		{
			ArtefactID: "12345678-1234-1234-1234-123456789abc",
			Status:     "draft",
			EarlyWarning: model.Art14EarlyWarning{
				Deadline: now.Add(-time.Hour),
			},
			Notification: model.Art14Notification{
				Deadline: now.Add(time.Hour),
				CVEIDs:   []string{"CVE-2026-0001"},
			},
		},
		{
			ArtefactID: "abcdefab-cdef-abcd-efab-cdefabcdefab",
			Status:     "dispatched:final-report",
		},
	}

	dashboard := buildArt14ListDashboard(artefacts, "artifacts")
	if len(dashboard.Findings) != 2 {
		t.Fatalf("expected two artefact cards, got %d", len(dashboard.Findings))
	}
	if dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("overdue draft should be high severity: %+v", dashboard.Findings[0])
	}
	if dashboard.Summary.Decision != "REVIEW" {
		t.Fatalf("expected review decision, got %q", dashboard.Summary.Decision)
	}
}

func TestBuildArt14ListDashboardChecksIntermediateDeadlines(t *testing.T) {
	now := time.Now().UTC()
	artefacts := []*model.Art14NotificationArtefact{{
		ArtefactID: "12345678-1234-1234-1234-123456789abc",
		Status:     "dispatched:early-warning",
		EarlyWarning: model.Art14EarlyWarning{
			Deadline: now.Add(-2 * time.Hour),
		},
		Notification: model.Art14Notification{
			Deadline: now.Add(-time.Hour),
		},
		FinalReport: model.Art14FinalReport{
			Deadline: now.Add(24 * time.Hour),
		},
	}}

	dashboard := buildArt14ListDashboard(artefacts, "artifacts")
	if dashboard.Findings[0].Severity != "HIGH" || dashboard.Summary.Decision != "REVIEW" {
		t.Fatalf("intermediate deadline was not surfaced: %+v", dashboard)
	}
}

func TestBuildArt14DetailDashboardMarksVerificationFailure(t *testing.T) {
	dashboard := buildArt14DetailDashboard(&model.Art14NotificationArtefact{
		ArtefactID: "12345678-1234-1234-1234-123456789abc",
		Status:     "draft",
	}, "verification failed")
	if dashboard.Summary.Decision != "FAILED" || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("verification failure was rendered as success: %+v", dashboard)
	}
}

func TestBuildArt14DetailDashboardDoesNotExposeFullHMAC(t *testing.T) {
	artefact := &model.Art14NotificationArtefact{
		ArtefactID: "12345678-1234-1234-1234-123456789abc",
		Status:     "draft",
		HMAC:       strings.Repeat("a", 64),
		Notification: model.Art14Notification{
			CVEIDs: []string{"CVE-2026-0001"},
		},
	}
	dashboard := buildArt14DetailDashboard(artefact, "verified")
	if dashboard.Summary.Decision != "VERIFIED" {
		t.Fatalf("verified action should not be reported as updated: %q", dashboard.Summary.Decision)
	}
	if len(dashboard.Findings) != 1 {
		t.Fatalf("expected detail card, got %d", len(dashboard.Findings))
	}
	card := dashboard.Findings[0]
	if card.Title != "CVE-2026-0001" {
		t.Fatalf("unexpected title: %q", card.Title)
	}
	for _, field := range card.Fields {
		if field.Label == "HMAC" && field.Value == artefact.HMAC {
			t.Fatal("full HMAC was exposed in dashboard")
		}
	}
}

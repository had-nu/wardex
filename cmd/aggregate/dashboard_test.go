// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package aggregate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/ui"
)

func TestAggregateDecisionPolicies(t *testing.T) {
	if combined, count, blocked := aggregateDecision(nil, "all-block"); combined != "ALLOW" || count != 0 || blocked {
		t.Fatalf("unexpected empty decision: %s %d %v", combined, count, blocked)
	}

	results := []fileResult{
		{file: "iso.json", decision: "block"},
		{file: "nis2.json", decision: "allow"},
	}

	if combined, count, blocked := aggregateDecision(results, "any-block"); combined != "BLOCK" || count != 1 || !blocked {
		t.Fatalf("unexpected any-block decision: %s %d %v", combined, count, blocked)
	}
	if combined, count, blocked := aggregateDecision(results, "all-block"); combined != "ALLOW" || count != 1 || blocked {
		t.Fatalf("unexpected all-block decision: %s %d %v", combined, count, blocked)
	}
}

func TestBuildAggregateDashboard(t *testing.T) {
	results := []fileResult{{
		file:     "iso.json",
		decision: "block",
		blocked:  2,
		allowed:  4,
		warned:   1,
	}}
	session := buildAggregateSession([]string{"iso.json", "nis2.json"})
	dashboard := buildAggregateDashboard(session, results, "any-block")

	if dashboard.Session.Status != "COMPLETE" {
		t.Fatalf("unexpected session status: %q", dashboard.Session.Status)
	}
	if len(dashboard.Findings) != 1 || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected finding cards: %+v", dashboard.Findings)
	}
	if dashboard.Summary.Decision != "BLOCK" {
		t.Fatalf("unexpected summary decision: %q", dashboard.Summary.Decision)
	}
}

func TestRenderAggregateTableDoesNotEmitANSIForBuffer(t *testing.T) {
	var out bytes.Buffer
	renderAggregateTable(&out, []fileResult{{file: "iso.json", decision: "allow"}})
	if strings.Contains(out.String(), "\033[") {
		t.Fatalf("non-terminal aggregate table contains ANSI: %q", out.String())
	}
}

func TestAggregateDashboardUsesNeutralSessionWhenEmpty(t *testing.T) {
	dashboard := buildAggregateDashboard(ui.SessionView{}, nil, "any-block")
	if dashboard.Session.Title != "AGGREGATION SESSION" {
		t.Fatalf("unexpected empty session title: %q", dashboard.Session.Title)
	}
}

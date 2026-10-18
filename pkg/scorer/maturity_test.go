// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer

import (
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// findingIn builds a covered finding in one domain with a known maturity.
func findingIn(domain string, maturity float64) model.Finding {
	return model.Finding{
		Control:           model.CatalogControl{ID: "X.1", Domain: domain},
		Status:            model.StatusCovered,
		EffectiveMaturity: maturity,
	}
}

func TestMaturityByDomainKeepsDomainsOutsideAnnexA(t *testing.T) {
	// NIS2 has always used "process", and this function dropped those findings
	// from the maturity average while warning on stderr. A report could then
	// state a maturity computed from only part of its own controls.
	findings := []model.Finding{
		findingIn("organizational", 3.0),
		findingIn("process", 5.0),
	}

	got := MaturityByDomain(findings)

	byDomain := map[string]model.DomainSummary{}
	for _, s := range got {
		byDomain[s.Domain] = s
	}

	process, ok := byDomain["process"]
	if !ok {
		t.Fatalf("MaturityByDomain() dropped the process domain entirely: %+v", got)
	}
	if process.TotalControls != 1 {
		t.Fatalf("process domain TotalControls = %d, want 1", process.TotalControls)
	}
	if process.MaturityScore != 5.0 {
		t.Fatalf("process domain MaturityScore = %v, want 5.0", process.MaturityScore)
	}
	if process.CoveragePercent != 100.0 {
		t.Fatalf("process domain CoveragePercent = %v, want 100", process.CoveragePercent)
	}
}

func TestMaturityByDomainCountsEveryFinding(t *testing.T) {
	// The aggregate that matters: no finding may fall out of the total, whatever
	// its domain.
	findings := []model.Finding{
		findingIn("organizational", 2.0),
		findingIn("process", 3.0),
		findingIn("governance", 4.0),
		findingIn("value_chain", 5.0),
		findingIn("people", 1.0),
	}

	got := MaturityByDomain(findings)

	total := 0
	for _, s := range got {
		total += s.TotalControls
	}
	if total != len(findings) {
		t.Fatalf("total controls across domains = %d, want %d: %+v", total, len(findings), got)
	}
}

func TestMaturityByDomainAlwaysReportsAnnexADomains(t *testing.T) {
	// A report should keep the same shape whatever the catalogue holds, so the
	// four Annex A domains appear even with no findings in them.
	got := MaturityByDomain([]model.Finding{findingIn("process", 3.0)})

	if len(got) < len(annexADomains) {
		t.Fatalf("MaturityByDomain() returned %d summaries, want at least %d", len(got), len(annexADomains))
	}
	for i, want := range annexADomains {
		if got[i].Domain != want {
			t.Fatalf("summary %d is %q, want %q; Annex A domains must come first in canonical order",
				i, got[i].Domain, want)
		}
		if got[i].TotalControls != 0 {
			t.Fatalf("%s TotalControls = %d, want 0", got[i].Domain, got[i].TotalControls)
		}
	}
}

func TestMaturityByDomainIsStableAcrossRuns(t *testing.T) {
	// The extra domains come from a map. Map iteration order is randomised in
	// Go, so an unsorted result would make the report differ between runs, which
	// is the defect the determinism work removed elsewhere.
	findings := []model.Finding{
		findingIn("zeta", 1.0),
		findingIn("alpha", 2.0),
		findingIn("process", 3.0),
		findingIn("governance", 4.0),
	}

	first := MaturityByDomain(findings)
	for range 200 {
		got := MaturityByDomain(findings)
		if len(got) != len(first) {
			t.Fatalf("length changed between runs: %d then %d", len(first), len(got))
		}
		for i := range got {
			if got[i].Domain != first[i].Domain {
				t.Fatalf("domain order changed between runs at %d: %q then %q",
					i, first[i].Domain, got[i].Domain)
			}
		}
	}
}

func TestMaturityByDomainAveragesWithinDomain(t *testing.T) {
	partial := model.Finding{
		Control:           model.CatalogControl{ID: "P.1", Domain: "process"},
		Status:            model.StatusPartial,
		EffectiveMaturity: 4.0,
	}
	gap := model.Finding{
		Control:           model.CatalogControl{ID: "P.2", Domain: "process"},
		Status:            model.StatusGap,
		EffectiveMaturity: 2.0,
	}

	got := MaturityByDomain([]model.Finding{partial, gap})

	for _, s := range got {
		if s.Domain != "process" {
			continue
		}
		if s.CoveredCount != 0 || s.PartialCount != 1 || s.GapCount != 1 {
			t.Fatalf("status counts = %d/%d/%d, want 0 covered, 1 partial, 1 gap",
				s.CoveredCount, s.PartialCount, s.GapCount)
		}
		if s.MaturityScore != 3.0 {
			t.Fatalf("MaturityScore = %v, want 3.0 (mean of 4 and 2)", s.MaturityScore)
		}
		return
	}
	t.Fatal("no summary for the process domain")
}

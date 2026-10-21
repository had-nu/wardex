// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer

import (
	"slices"
	"sort"

	"github.com/had-nu/wardex/v3/pkg/model"
)

// annexADomains are the four Annex A domains. They are always reported, even
// when a run has no findings in them, so that a report shows the same shape
// whatever the catalogue holds.
var annexADomains = []string{"organizational", "people", "physical", "technological"}

// MaturityByDomain calculates maturity scores aggregated by domain.
//
// Domains outside the Annex A four are reported too, rather than dropped.
// NIS2 already used "process" and this function excluded those controls from
// the maturity average while printing a warning to stderr, so a report could
// state a maturity figure that silently omitted a quarter of the controls it
// was computed from. A catalogue author adding a domain should not have to know
// that this file exists.
func MaturityByDomain(findings []model.Finding) []model.DomainSummary {
	summaries := make(map[string]*model.DomainSummary)
	for _, d := range annexADomains {
		summaries[d] = newDomainSummary(d)
	}

	for _, f := range findings {
		s, ok := summaries[f.Control.Domain]
		if !ok {
			s = newDomainSummary(f.Control.Domain)
			summaries[f.Control.Domain] = s
		}

		s.TotalControls++

		switch f.Status {
		case model.StatusCovered:
			s.CoveredCount++
		case model.StatusPartial:
			s.PartialCount++
		case model.StatusGap:
			s.GapCount++
		}

		// Calculate maturity contribution using the v1.8.0 EffectiveMaturity
		s.MaturityScore += f.EffectiveMaturity
	}

	// Annex A domains first in their canonical order, then any other domain in
	// a stable order, so the report does not reshuffle between runs.
	var extra []string
	for d := range summaries {
		if !slices.Contains(annexADomains, d) {
			extra = append(extra, d)
		}
	}
	sort.Strings(extra)

	result := make([]model.DomainSummary, 0, len(summaries))
	for _, d := range annexADomains {
		result = append(result, *summaries[d])
	}
	for _, d := range extra {
		result = append(result, *summaries[d])
	}

	for i := range result {
		s := &result[i]
		if s.TotalControls == 0 {
			continue
		}
		s.CoveragePercent = float64(s.CoveredCount) / float64(s.TotalControls) * 100.0
		s.MaturityScore = s.MaturityScore / float64(s.TotalControls)
	}

	return result
}

// newDomainSummary returns an empty summary for one domain.
func newDomainSummary(domain string) *model.DomainSummary {
	return &model.DomainSummary{Domain: domain}
}

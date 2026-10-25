// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package correlator_test

import (
	"slices"
	"testing"

	"github.com/had-nu/wardex/v3/pkg/catalog"
	"github.com/had-nu/wardex/v3/pkg/correlator"
	"github.com/had-nu/wardex/v3/pkg/model"
)

// TestCatalogueControlsMatchDeclarativelyOnTheirDomain is the behaviour half
// of M0-P0.2. Only annex_a.yaml declares `domains`; every other catalogue
// declares `domain` alone. Before Load derived the list, matchDomains saw an
// empty set on those catalogues and every correlation fell back to keyword
// inference (low confidence). The declarative path must now be reachable for
// every framework, and the matched domain must be reported.
func TestCatalogueControlsMatchDeclarativelyOnTheirDomain(t *testing.T) {
	for _, key := range catalog.Keys() {
		t.Run(key, func(t *testing.T) {
			controls, err := catalog.Load(key)
			if err != nil {
				t.Fatalf("Load(%q): %v", key, err)
			}

			var target model.CatalogControl
			for _, c := range controls {
				if c.Domain != "" {
					target = c
					break
				}
			}
			if target.ID == "" {
				t.Fatalf("%s: no control declares a domain", key)
			}

			existing := model.ExistingControl{
				ID:      "CTRL-1",
				Domains: []string{target.Domain},
			}
			res := correlator.Match(existing, target)
			if !res.Matched || res.Confidence != "high" {
				t.Fatalf("Match(%s) = %+v; want a high-confidence declarative match on domain %q",
					target.ID, res, target.Domain)
			}
			if !slices.Contains(res.MatchedDomains, target.Domain) {
				t.Fatalf("Match(%s) reported domains %v; want %q",
					target.ID, res.MatchedDomains, target.Domain)
			}
		})
	}
}

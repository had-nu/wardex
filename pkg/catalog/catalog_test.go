// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v3/pkg/catalog"
)

func TestCatalogLoad(t *testing.T) {
	controls, err := catalog.Load("iso27001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 93 {
		t.Errorf("expected 93 controls, got %d", len(controls))
	}

	for _, c := range controls {
		if c.BaseScore < 0.0 || c.BaseScore > 10.0 {
			t.Errorf("control %s base_score %f out of bounds", c.ID, c.BaseScore)
		}

		if c.ID == "A.8.8" {
			foundGateRelevant := false
			for _, p := range c.Practices {
				if p.GateRelevant {
					foundGateRelevant = true
				}
			}
			if !foundGateRelevant {
				t.Errorf("expected A.8.8 to have at least one GateRelevant practice")
			}
		}
	}
}

// TestEveryRegisteredFrameworkLoads holds the whole registry to the same
// contract as the ISO catalogue.
//
// The previous test read one framework by name, so a YAML file that failed to
// embed, a control outside the score bounds, or a duplicated practice id in any
// of the other catalogues would pass the suite. A framework is a data file with
// no other check on it, which makes this the only place a mistake surfaces.
func TestEveryRegisteredFrameworkLoads(t *testing.T) {
	keys := catalog.Keys()
	if len(keys) == 0 {
		t.Fatal("registry is empty")
	}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			controls, err := catalog.Load(key)
			if err != nil {
				t.Fatalf("Load(%q): %v", key, err)
			}
			if len(controls) == 0 {
				t.Fatalf("Load(%q) returned no controls", key)
			}

			if _, ok := catalog.DisplayName(key); !ok {
				t.Errorf("Load(%q) works but DisplayName(%q) does not", key, key)
			}

			seenControl := map[string]bool{}
			seenPractice := map[string]bool{}
			for _, c := range controls {
				if c.ID == "" {
					t.Errorf("%s: a control has an empty id", key)
					continue
				}
				if seenControl[c.ID] {
					t.Errorf("%s: duplicate control id %s", key, c.ID)
				}
				seenControl[c.ID] = true

				if c.Name == "" {
					t.Errorf("%s: control %s has no name", key, c.ID)
				}
				if c.Domain == "" {
					t.Errorf("%s: control %s has no domain", key, c.ID)
				}
				if c.BaseScore < 0.0 || c.BaseScore > 10.0 {
					t.Errorf("%s: control %s base_score %f out of bounds", key, c.ID, c.BaseScore)
				}

				for _, p := range c.Practices {
					if p.ID == "" {
						t.Errorf("%s: control %s has a practice with no id", key, c.ID)
						continue
					}
					if seenPractice[p.ID] {
						t.Errorf("%s: duplicate practice id %s", key, p.ID)
					}
					seenPractice[p.ID] = true

					if p.MinMaturity < 0 || p.MinMaturity > 5 {
						t.Errorf("%s: practice %s min_maturity %d out of bounds", key, p.ID, p.MinMaturity)
					}
				}
			}
		})
	}
}

// TestUnsupportedFrameworkNamesEveryKey pins the error message to the registry.
// A literal list here would rot exactly as one did in the assess hint.
func TestUnsupportedFrameworkNamesEveryKey(t *testing.T) {
	_, err := catalog.Load("no-such-framework")
	if err == nil {
		t.Fatal("Load of an unknown framework returned no error")
	}
	for _, key := range catalog.Keys() {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error message omits registered framework %q:\n%s", key, err)
		}
	}
}

// retiredFrameworks were supported and are not any more, with the reason.
//
// This is a list of absences on purpose. Removing a framework touches the
// registry, its catalogue, the policy files, the Helm ConfigMap, the Action
// metadata and six documents, and every one of those is a place a stale
// reference can survive. SOC 2 was removed because Wardex is built for the
// European market and it is an AICPA framework with no standing in EU law.
var retiredFrameworks = map[string]string{
	"soc2": "AICPA framework, no standing in EU law; Wardex targets the European market",
}

func TestRetiredFrameworksAreGone(t *testing.T) {
	for key, reason := range retiredFrameworks {
		t.Run(key, func(t *testing.T) {
			if _, ok := catalog.DisplayName(key); ok {
				t.Errorf("%s is still registered; it was retired because %s", key, reason)
			}
			if _, err := catalog.Load(key); err == nil {
				t.Errorf("Load(%q) still succeeds", key)
			}
		})
	}
}

// TestEveryRegisteredFrameworkIsInEuropeanScope guards the registry against
// quietly regaining a framework that belongs to another regime. It is a
// reminder rather than a legal test: the reason column is the one to update
// when this fails.
func TestEveryRegisteredFrameworkIsInEuropeanScope(t *testing.T) {
	// Each of these is in force in the European Union or is an international
	// standard that EU regulation and audit practice routinely require.
	inScope := map[string]string{
		"iso27001":  "ISO/IEC 27001, widely required by EU regulation and procurement",
		"eu_ai_act": "Regulation (EU) 2024/1689, the EU AI Act",
		"cra":       "Regulation (EU) 2024/2847, the Cyber Resilience Act",
		"dora":      "Regulation (EU) 2022/2554, DORA for the financial sector",
		"nis2":      "Directive (EU) 2022/2555, NIS2",
		"gdpr":      "Regulation (EU) 2016/679, the GDPR",
		"nist_csf":  "NIST CSF, referenced by NIS2 and by EU procurement",
	}

	for _, key := range catalog.Keys() {
		if _, ok := inScope[key]; !ok {
			t.Errorf("framework %q is registered but has no recorded European basis; add it to inScope with the reason, or retire it", key)
		}
	}
}

// TestEveryCatalogueControlCarriesItsDomainInDomains is the data-level half of
// M0-P0.2. The correlator's declarative path reads CatalogControl.Domains, and
// only annex_a.yaml used to declare that list; the other six catalogues
// declared `domain` alone, so their controls could never match declaratively.
// Load now derives the list, and this test holds every catalogue to it.
func TestEveryCatalogueControlCarriesItsDomainInDomains(t *testing.T) {
	for _, key := range catalog.Keys() {
		t.Run(key, func(t *testing.T) {
			controls, err := catalog.Load(key)
			if err != nil {
				t.Fatalf("Load(%q): %v", key, err)
			}
			for _, c := range controls {
				if len(c.Domains) == 0 {
					t.Errorf("%s: control %s has no domains", key, c.ID)
					continue
				}
				if c.Domain != "" && !slices.Contains(c.Domains, c.Domain) {
					t.Errorf("%s: control %s domain %q is not in domains %v", key, c.ID, c.Domain, c.Domains)
				}
			}
		})
	}
}

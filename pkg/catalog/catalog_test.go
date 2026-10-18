// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/catalog"
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

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/catalog"
)

// craControls loads the Cyber Resilience Act catalogue.
func craControls(t *testing.T) []struct{ ID, Name string } {
	t.Helper()

	controls, err := catalog.Load("cra")
	if err != nil {
		t.Fatalf("Load(cra): %v", err)
	}

	out := make([]struct{ ID, Name string }, 0, len(controls))
	for _, c := range controls {
		out = append(out, struct{ ID, Name string }{c.ID, c.Name})
	}
	return out
}

// TestCRAProvisionInTheNameMatchesTheIdentifier checks that the provision a
// control cites in its name is the provision the identifier names.
//
// Without this, an identifier and its name can drift apart: renaming "Annex I
// Part II (8)" to "(9)" keeps every other assertion in this file passing,
// because the name still contains the word Annex. A catalogue whose names cite
// provisions that do not exist is worse than one whose names cite none, because
// the number looks authoritative to a reader.
func TestCRAProvisionInTheNameMatchesTheIdentifier(t *testing.T) {
	// Each entry builds the provision reference the name must contain, from the
	// identifier itself. A constant fragment would not notice a name citing a
	// different paragraph from the one its identifier names.
	patterns := []struct {
		id     *regexp.Regexp
		expect func(id string) string
	}{
		{
			id: regexp.MustCompile(`^CRA\.Art(\d+)\.(\d+)[a-z]?$`),
			expect: func(id string) string {
				m := regexp.MustCompile(`^CRA\.Art(\d+)\.(\d+)[a-z]?$`).FindStringSubmatch(id)
				return "Art. " + m[1] + "(" + m[2] + ")"
			},
		},
		{
			id: regexp.MustCompile(`^CRA\.AnnexI\.1\.2([a-z])$`),
			expect: func(id string) string {
				m := regexp.MustCompile(`^CRA\.AnnexI\.1\.2([a-z])$`).FindStringSubmatch(id)
				return "Part I (2)(" + m[1] + ")"
			},
		},
		{
			id: regexp.MustCompile(`^CRA\.AnnexI\.2\.(\d+)$`),
			expect: func(id string) string {
				m := regexp.MustCompile(`^CRA\.AnnexI\.2\.(\d+)$`).FindStringSubmatch(id)
				return "Part II (" + m[1] + ")"
			},
		},
		{
			id: regexp.MustCompile(`^CRA\.AnnexVII\.(\d+)$`),
			expect: func(id string) string {
				m := regexp.MustCompile(`^CRA\.AnnexVII\.(\d+)$`).FindStringSubmatch(id)
				return "Annex VII (" + m[1] + ")"
			},
		},
		{
			id: regexp.MustCompile(`^CRA\.AnnexV\.(\d+)$`),
			expect: func(id string) string {
				m := regexp.MustCompile(`^CRA\.AnnexV\.(\d+)$`).FindStringSubmatch(id)
				return "Annex V (" + m[1] + ")"
			},
		},
	}

	for _, c := range craControls(t) {
		for _, p := range patterns {
			if !p.id.MatchString(c.ID) {
				continue
			}
			fragment := p.expect(c.ID)
			if !strings.Contains(c.Name, fragment) {
				t.Errorf("control %s is named %q, which does not contain %q; the identifier and the cited provision must agree",
					c.ID, c.Name, fragment)
			}
			break
		}
	}
}

// TestCRAAnnexIRequirementsAreAllPresent covers Annex I Part I point (2), which
// has four lettered requirements and Part II, which has eight. Both are
// enumerated in the Regulation and a catalogue that drops one silently under
// states coverage.
func TestCRAAnnexIRequirementsAreAllPresent(t *testing.T) {
	controls := craControls(t)

	present := map[string]bool{}
	for _, c := range controls {
		present[c.ID] = true
	}

	for _, letter := range []string{"a", "b", "c", "d"} {
		id := "CRA.AnnexI.1.2" + letter
		if !present[id] {
			t.Errorf("Annex I Part I (2)(%s) has no control; the Regulation lists four lettered requirements", letter)
		}
	}
	for i := 1; i <= 8; i++ {
		id := "CRA.AnnexI.2." + itoa(i)
		if !present[id] {
			t.Errorf("%s has no control; Annex I Part II lists eight requirements", id)
		}
	}
}

// TestCRAAnnexVIIFieldsAreAllPresent covers the eight fields of the technical
// documentation. Field 4 is the support-period rationale, which is what links
// Annex VII to Article 13(8); a catalogue that omits it drops the only Annex VII
// field Wardex can reason about from its own inputs.
func TestCRAAnnexVIIFieldsAreAllPresent(t *testing.T) {
	controls := craControls(t)

	present := map[string]string{}
	for _, c := range controls {
		present[c.ID] = c.Name
	}

	for i := 1; i <= 8; i++ {
		id := "CRA.AnnexVII." + itoa(i)
		if _, ok := present[id]; !ok {
			t.Errorf("Annex VII (%d) has no control; the Regulation lists eight fields", i)
		}
	}

	if name := present["CRA.AnnexVII.4"]; !strings.Contains(name, "13(8)") {
		t.Errorf("Annex VII (4) is %q; it is the field for information taken into account to determine the support period under Article 13(8)", name)
	}
}

// TestCRASupportPeriodStatesTheFiveYearRuleWithItsException pins the Article
// 13(8) wording. "At least five years" is not an unconditional floor: where the
// product is expected to be in use for less than five years, the support period
// corresponds to that expected use time. A control that states only the five
// year rule overstates the obligation for a short-lived product.
func TestCRASupportPeriodStatesTheFiveYearRuleWithItsException(t *testing.T) {
	controls := craControls(t)

	var control *struct{ ID, Name string }
	for i, c := range controls {
		if c.ID == "CRA.Art13.8" {
			control = &controls[i]
			break
		}
	}
	if control == nil {
		t.Fatal("no control for Article 13(8)")
	}

	lowered := strings.ToLower(control.Name)
	if !strings.Contains(lowered, "five years") {
		t.Errorf("Article 13(8) control name %q does not mention the five year rule", control.Name)
	}
	if !strings.Contains(lowered, "shorter") && !strings.Contains(lowered, "less than") {
		t.Errorf("Article 13(8) control name %q omits the exception where expected use is shorter than five years", control.Name)
	}
}

// TestCRAAnnexVFieldsAreAllPresent covers the eight fields of the EU declaration
// of conformity, which Article 28(2) requires and Annex V prescribes.
func TestCRAAnnexVFieldsAreAllPresent(t *testing.T) {
	present := map[string]bool{}
	for _, c := range craControls(t) {
		present[c.ID] = true
	}
	for i := 1; i <= 8; i++ {
		id := "CRA.AnnexV." + itoa(i)
		if !present[id] {
			t.Errorf("Annex V (%d) has no control; the Regulation lists eight declaration fields", i)
		}
	}
}

// TestCRAIdentifiersUseTheDeclaredScheme checks that no identifier invents a
// scheme. The NIS2 catalogue once numbered twenty-five controls as Article
// 21(2)(a) to (y) where the Directive lists ten; the same failure here would
// assert a provenance the Regulation does not have.
func TestCRAIdentifiersUseTheDeclaredScheme(t *testing.T) {
	patterns := map[string]*regexp.Regexp{
		"article":    regexp.MustCompile(`^CRA\.Art\d+\.\d+[a-z]?$`),
		"annexI":     regexp.MustCompile(`^CRA\.AnnexI\.[12]\.\d+[a-z]?$`),
		"annexVII":   regexp.MustCompile(`^CRA\.Annex(VII|V)\.\d+(\.\d+)?$`),
		"supporting": regexp.MustCompile(`^CRA\.SUP\.[a-z]$`),
	}

	for _, c := range craControls(t) {
		matched := false
		for scheme, p := range patterns {
			if p.MatchString(c.ID) {
				matched = true
				_ = scheme
				break
			}
		}
		if !matched {
			t.Errorf("control %s uses an identifier that matches none of the schemes declared in the file header", c.ID)
		}
	}
}

// TestCRAControlsCiteTheirProvision keeps the report line self-evidencing, the
// same rule the GDPR and NIS2 catalogues are held to.
func TestCRAControlsCiteTheirProvision(t *testing.T) {
	for _, c := range craControls(t) {
		if !strings.Contains(c.Name, "Art.") && !strings.Contains(c.Name, "Annex") {
			t.Errorf("control %s does not cite its provision in the name: %q", c.ID, c.Name)
		}
	}
}

// TestCRAExcludesOtherEconomicOperators checks that importer, distributor and
// authorised representative duties are absent. They are real obligations but
// they bind different actors, and scoring them as a manufacturer's own would
// invite a report to claim compliance it does not have.
func TestCRAExcludesOtherEconomicOperators(t *testing.T) {
	// Articles 18 to 22 in the Regulation.
	for _, c := range craControls(t) {
		if strings.HasPrefix(c.ID, "CRA.Art18") || strings.HasPrefix(c.ID, "CRA.Art19") ||
			strings.HasPrefix(c.ID, "CRA.Art20") || strings.HasPrefix(c.ID, "CRA.Art21") ||
			strings.HasPrefix(c.ID, "CRA.Art22") {
			t.Errorf("catalogue contains %s, an obligation on importers, distributors or authorised representatives rather than the manufacturer", c.ID)
		}
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

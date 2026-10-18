// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/catalog"
)

// article212Letters are the ten lettered items of Article 21(2) of Directive
// (EU) 2022/2555. The Directive lists (a) to (j) and no further.
//
// An earlier revision of nis2.yaml numbered twenty-five controls as
// NIS2.21.2.a through NIS2.21.2.y. Fifteen of those identifiers corresponded to
// nothing in the Directive, four more carried the wrong letter, and the
// obligation to assess the effectiveness of the measures was missing. The
// obligation itself was described correctly in doc/regulatory-context.md, so
// two artefacts shipped in the same release disagreed about what Article 21(2)(f)
// says.
var article212Letters = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}

// directiveItem is a letter of Article 21(2) with the subject the Directive
// assigns to it, taken from CELEX 32022L2555.
var directiveItemSubjects = map[string]string{
	"a": "risk analysis",
	"b": "incident handling",
	"c": "business continuity",
	"d": "supply chain",
	"e": "vulnerability",
	"f": "effectiveness",
	"g": "cyber hygiene",
	"h": "cryptography",
	"i": "human resources",
	"j": "multi-factor",
}

// TestNIS2Article212HasExactlyTheTenItems checks the lettered identifiers
// against the ten the Directive defines. A control that is not a lettered item
// of the Directive must not carry that identifier.
func TestNIS2Article212HasExactlyTheTenItems(t *testing.T) {
	controls, err := catalog.Load("nis2")
	if err != nil {
		t.Fatalf("Load(nis2): %v", err)
	}

	seen := map[string]string{}
	for _, c := range controls {
		if !strings.HasPrefix(c.ID, "NIS2.21.2.") {
			continue
		}
		letter := strings.TrimPrefix(c.ID, "NIS2.21.2.")
		if !slices.Contains(article212Letters, letter) {
			t.Errorf("control %s claims to be a lettered item of Article 21(2); the Directive lists only (a) to (j)",
				c.ID)
			continue
		}
		if prev, dup := seen[letter]; dup {
			t.Errorf("two controls claim Article 21(2)(%s): %s and %s", letter, prev, c.ID)
		}
		seen[letter] = c.ID
	}

	for _, letter := range article212Letters {
		if _, ok := seen[letter]; !ok {
			t.Errorf("Article 21(2)(%s) has no control in the catalogue", letter)
		}
	}
}

// TestNIS2Article212SubjectsMatchTheDirective checks that each lettered control
// is about the subject the Directive assigns to that letter.
//
// A name check cannot prove the wording matches the Official Journal. It does
// prove that a control has not been moved to a letter whose subject is
// different, which is the failure mode that produced the original defect: the
// cryptography control carried letter (f), whose subject is effectiveness.
func TestNIS2Article212SubjectsMatchTheDirective(t *testing.T) {
	controls, err := catalog.Load("nis2")
	if err != nil {
		t.Fatalf("Load(nis2): %v", err)
	}

	byLetter := map[string]string{}
	for _, c := range controls {
		if after, ok := strings.CutPrefix(c.ID, "NIS2.21.2."); ok {
			byLetter[after] = strings.ToLower(c.Name)
		}
	}

	for _, letter := range article212Letters {
		name, ok := byLetter[letter]
		if !ok {
			t.Errorf("Article 21(2)(%s) has no control to check", letter)
			continue
		}
		subject := directiveItemSubjects[letter]
		if !strings.Contains(name, subject) {
			t.Errorf("control for Article 21(2)(%s) is %q, which does not mention %q; the Directive assigns %q to that letter",
				letter, name, subject, subject)
		}
	}
}

// TestNIS2SupplementaryIDsAreDistinct checks that a supporting measure carries a
// supplementary identifier rather than a Directive identifier.
func TestNIS2SupplementaryIDsAreDistinct(t *testing.T) {
	controls, err := catalog.Load("nis2")
	if err != nil {
		t.Fatalf("Load(nis2): %v", err)
	}

	supPattern := regexp.MustCompile(`^NIS2\.SUP\.[a-z]+$`)
	// A Directive identifier: article, optional paragraph, optional letter. The
	// letter is absent for controls addressing a whole article or a paragraph
	// that is not lettered, such as Article 23(4).
	articlePattern := regexp.MustCompile(`^NIS2\.[0-9]+(\.[0-9]+)*(\.[a-z]+)?$`)

	supplementary := 0
	for _, c := range controls {
		switch {
		case supPattern.MatchString(c.ID):
			supplementary++
		case articlePattern.MatchString(c.ID):
			// A Directive identifier is legitimate; its subject is checked above.
		default:
			t.Errorf("control %s uses an identifier that matches neither a Directive article nor the supplementary scheme", c.ID)
		}
	}

	if supplementary == 0 {
		t.Error("no supplementary controls found; the scheme in the file header is not being used")
	}
}

// TestEveryControlNameNamesItsSource checks that controls in a legal catalogue
// cite the provision they come from. A reader who sees "Art. 21(2)(f)" in a
// report is entitled to assume it is the Directive's own lettering.
func TestEveryControlNameNamesItsSource(t *testing.T) {
	for _, key := range []string{"nis2", "gdpr"} {
		t.Run(key, func(t *testing.T) {
			controls, err := catalog.Load(key)
			if err != nil {
				t.Fatalf("Load(%s): %v", key, err)
			}

			for _, c := range controls {
				needsCitation := strings.HasPrefix(c.ID, "NIS2.") && !strings.HasPrefix(c.ID, "NIS2.SUP.")
				needsCitation = needsCitation || strings.HasPrefix(c.ID, "GDPR.")
				if !needsCitation {
					continue
				}
				if !strings.Contains(c.Name, "Art.") {
					t.Errorf("%s: control %s does not cite its provision in the name: %q",
						key, c.ID, c.Name)
				}
			}
		})
	}
}

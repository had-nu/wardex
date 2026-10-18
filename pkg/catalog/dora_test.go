// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/catalog"
)

// doraArticleTitles are the titles Regulation (EU) 2022/2554 gives its articles,
// for the articles this catalogue draws on.
//
// Transcribed rather than read at run time because the Regulation is not in the
// repository. The point is to catch a catalogue that has drifted from the
// Regulation, not to reproduce it.
var doraArticleTitles = map[int]string{
	5:  "Governance and organisation",
	6:  "ICT risk management framework",
	7:  "ICT systems, protocols and tools",
	8:  "Identification",
	9:  "Protection and prevention",
	10: "Detection",
	11: "Response and recovery",
	12: "Backup policies and procedures, restoration and recovery procedures and methods",
	13: "Learning and evolving",
	14: "Communication",
	15: "Further harmonisation of ICT risk management tools, methods, processes and policies",
	16: "Simplified ICT risk management framework",
	17: "ICT-related incident management process",
	18: "Classification of ICT-related incidents and cyber threats",
	19: "Reporting of major ICT-related incidents and voluntary notification of significant cyber threats",
	20: "Harmonisation of reporting content and templates",
	21: "Centralisation of reporting of major ICT-related incidents",
	22: "Supervisory feedback",
	23: "Operational or security payment-related incidents concerning credit institutions and certain payment institutions",
	24: "General requirements for the performance of digital operational resilience testing",
	25: "Testing of ICT tools and systems",
	26: "Advanced testing of ICT tools, systems and processes based on threat-led penetration testing",
	27: "Requirements for testers for the carrying out of threat-led penetration testing",
	28: "General principles",
	29: "Preliminary assessment of ICT concentration risk at entity level",
	30: "Key contractual provisions",
	31: "Designation of critical ICT third-party service providers",
	45: "Information-sharing arrangements on cyber threat information and intelligence",
}

var doraIDPattern = regexp.MustCompile(`^DORA\.Art(\d+)(\.\d+)?$`)

// stop words are excluded when comparing a control name against an article
// title, so that "and" or "of" does not count as agreement.
var stop = map[string]bool{
	"the": true, "and": true, "for": true, "of": true, "a": true, "an": true,
	"with": true, "on": true, "in": true, "to": true, "or": true, "its": true,
	"that": true, "are": true, "by": true,
}

// TestDORAControlsSitUnderTheArticleWhoseSubjectTheyDescribe is the check that
// was missing for NIS2, for NIST CSF and for DORA itself.
//
// The previous DORA catalogue numbered twenty-six controls over Articles 5 to 30
// consecutively. Sixteen of them sat under an article whose subject was unrelated
// to what the control described: Art 30 carried "Financial Impact Reporting"
// while Article 30 is "Key contractual provisions", and Art 17 carried "Key
// Contractual Provisions" while Article 17 is the incident management process.
//
// A consecutive run is the tell. A real instrument is not covered by an
// unbroken range of articles.
func TestDORAControlsSitUnderTheArticleWhoseSubjectTheyDescribe(t *testing.T) {
	controls, err := catalog.Load("dora")
	if err != nil {
		t.Fatalf("Load(dora): %v", err)
	}

	for _, c := range controls {
		m := doraIDPattern.FindStringSubmatch(c.ID)
		if m == nil {
			t.Errorf("control %q does not use the DORA.Art<N> identifier form", c.ID)
			continue
		}

		var n int
		for _, r := range m[1] {
			n = n*10 + int(r-'0')
		}

		title, known := doraArticleTitles[n]
		if !known {
			t.Errorf("control %s names article %d, which is not one this catalogue is built on", c.ID, n)
			continue
		}

		// The control's name must share a distinctive word with the article's
		// own title. Sharing nothing means the identifier and the subject have
		// come apart.
		titleWords := distinctive(title)
		nameWords := distinctive(c.Name)
		if len(titleWords) == 0 {
			continue
		}
		shared := 0
		for w := range titleWords {
			if nameWords[w] {
				shared++
			}
		}
		if shared == 0 {
			t.Errorf("control %s is named %q, which shares no word with article %d (%q); "+
				"the identifier and the subject disagree",
				c.ID, c.Name, n, title)
		}
	}
}

// distinctive returns the content words of s, lowercased.
func distinctive(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r < 'a' || r > 'z'
	}) {
		if len(w) > 3 && !stop[w] {
			out[w] = true
		}
	}
	return out
}

// TestDORADoesNotCoverArticlesConsecutively catches the shape of the defect
// directly. A catalogue that assigns one control to each article of an unbroken
// range was written from an outline, not from the instrument.
func TestDORADoesNotCoverArticlesConsecutively(t *testing.T) {
	controls, err := catalog.Load("dora")
	if err != nil {
		t.Fatalf("Load(dora): %v", err)
	}

	seen := map[int]bool{}
	minN, maxN := 999, 0
	for _, c := range controls {
		m := doraIDPattern.FindStringSubmatch(c.ID)
		if m == nil {
			continue
		}
		var n int
		for _, r := range m[1] {
			n = n*10 + int(r-'0')
		}
		seen[n] = true
		if n < minN {
			minN = n
		}
		if n > maxN {
			maxN = n
		}
	}

	span := maxN - minN + 1
	if span > 0 && len(seen) == span {
		t.Errorf("the catalogue covers every article from %d to %d with no gaps; "+
			"Regulation 2022/2554 is not covered by an unbroken range of articles", minN, maxN)
	}
}

// TestDORAOmitsArticlesThatBindAuthorities checks the scope decision recorded in
// the file header. Articles 32 to 44 and 46 to 56 concern the Lead Overseer,
// supervisory authorities and administrative penalties; an entity scoring itself
// against this catalogue should not be handed obligations that are not its own.
func TestDORAOmitsArticlesThatBindAuthorities(t *testing.T) {
	controls, err := catalog.Load("dora")
	if err != nil {
		t.Fatalf("Load(dora): %v", err)
	}

	authorityArticles := []int{32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
		46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56}

	for _, c := range controls {
		m := doraIDPattern.FindStringSubmatch(c.ID)
		if m == nil {
			continue
		}
		var n int
		for _, r := range m[1] {
			n = n*10 + int(r-'0')
		}
		for _, a := range authorityArticles {
			if n == a {
				t.Errorf("control %s is on article %d, which binds the Lead Overseer or a supervisory authority rather than a financial entity", c.ID, n)
			}
		}
	}
}

// TestDORAIdentifiersUseTheDeclaredForm keeps the scheme honest: an article
// number, optionally followed by a sub-number when the article carries more
// than one distinct obligation.
func TestDORAIdentifiersUseTheDeclaredForm(t *testing.T) {
	controls, err := catalog.Load("dora")
	if err != nil {
		t.Fatalf("Load(dora): %v", err)
	}
	for _, c := range controls {
		if !doraIDPattern.MatchString(c.ID) {
			t.Errorf("control %q does not use the DORA.Art<N> form", c.ID)
		}
	}
}

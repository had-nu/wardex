// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"regexp"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/catalog"
)

// aiactArticleTitles are the titles Regulation (EU) 2024/1689 gives its articles,
// for the articles this catalogue draws on.
//
// Transcribed rather than read at run time because the Regulation is not in the
// repository. The point is to catch a catalogue that has drifted from the
// Regulation, not to reproduce it.
var aiactArticleTitles = map[int]string{
	4:  "AI literacy",
	5:  "Prohibited AI practices",
	6:  "Classification rules for high-risk AI systems",
	9:  "Risk management system",
	10: "Data and data governance",
	11: "Technical documentation",
	12: "Record-keeping",
	13: "Transparency and provision of information to deployers",
	14: "Human oversight",
	15: "Accuracy, robustness and cybersecurity",
	16: "Obligations of providers of high-risk AI systems",
	17: "Quality management system",
	18: "Documentation keeping",
	19: "Automatically generated logs",
	20: "Corrective actions and duty of information",
	21: "Cooperation with competent authorities",
	22: "Authorised representatives of providers of high-risk AI systems",
	23: "Obligations of importers",
	24: "Obligations of distributors",
	25: "Responsibilities along the AI value chain",
	26: "Obligations of deployers of high-risk AI systems",
	27: "Fundamental rights impact assessment for high-risk AI systems",
	43: "Conformity assessment",
	47: "EU declaration of conformity",
	49: "Registration",
	50: "Transparency obligations for providers and deployers of certain AI systems",
	53: "Obligations for providers of general-purpose AI models",
	55: "Obligations of providers of general-purpose AI models with systemic risk",
	72: "Post-market monitoring by providers and post-market monitoring plan for high-risk AI systems",
	73: "Reporting of serious incidents",
	99: "Penalties",
}

var aiactIDPattern = regexp.MustCompile(`^EUAIA\.Art(\d+)$`)

// aiactAuthorityArticles bind authorities rather than a provider or a deployer,
// and are excluded by the scope decision recorded in the file header.
var aiactAuthorityArticles = []int{28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 44, 45, 46, 64, 65, 66, 67, 68, 69, 70, 74, 75, 76, 77, 78, 79}

// TestAIActControlsSitUnderTheArticleWhoseSubjectTheyDescribe compares each
// control's name against the article's own title.
//
// The same assertion is applied to the NIS2, NIST CSF and DORA catalogues, and in
// each case it is the check that would have caught the defect. This catalogue
// passed it on first reading, which is worth holding: a framework added later
// should not regress to the state the others were in.
//
// What this does not catch. It asks whether the name shares any content word with
// the article, so a control whose name borrows one word from the right title while
// describing a different article passes. Tightening it does not work: these names
// are paraphrases rather than quotations, and eleven of the thirty-one would fail
// a requirement of full overlap. A nearest-neighbour variant was tried and
// rejected, because a control on obligations of importers legitimately references
// the technical documentation and the conformity assessment of other articles.
// The residual gap is a name that reuses the vocabulary of its own article while
// describing another, and a lexical check cannot see that.
func TestAIActControlsSitUnderTheArticleWhoseSubjectTheyDescribe(t *testing.T) {
	controls, err := catalog.Load("eu_ai_act")
	if err != nil {
		t.Fatalf("Load(eu_ai_act): %v", err)
	}
	if len(controls) == 0 {
		t.Fatal("catalogue is empty")
	}

	for _, c := range controls {
		m := aiactIDPattern.FindStringSubmatch(c.ID)
		if m == nil {
			t.Errorf("control %q does not use the EUAIA.Art<N> identifier form", c.ID)
			continue
		}

		var n int
		for _, r := range m[1] {
			n = n*10 + int(r-'0')
		}

		title, known := aiactArticleTitles[n]
		if !known {
			t.Errorf("control %s names article %d, which is not one this catalogue is built on", c.ID, n)
			continue
		}

		shared := 0
		for w := range distinctive(title) {
			if distinctive(c.Name)[w] {
				shared++
			}
		}
		if shared == 0 {
			t.Errorf("control %s is named %q, which shares no word with article %d (%q); "+
				"the identifier and the subject disagree", c.ID, c.Name, n, title)
		}
	}
}

// TestAIActIdentifiersUseTheDeclaredForm keeps the scheme honest: an article
// number, nothing else.
func TestAIActIdentifiersUseTheDeclaredForm(t *testing.T) {
	controls, err := catalog.Load("eu_ai_act")
	if err != nil {
		t.Fatalf("Load(eu_ai_act): %v", err)
	}
	for _, c := range controls {
		if !aiactIDPattern.MatchString(c.ID) {
			t.Errorf("control %q does not use the EUAIA.Art<N> form", c.ID)
		}
	}
}

// TestAIActOmitsArticlesThatBindAuthorities holds the scope decision.
func TestAIActOmitsArticlesThatBindAuthorities(t *testing.T) {
	controls, err := catalog.Load("eu_ai_act")
	if err != nil {
		t.Fatalf("Load(eu_ai_act): %v", err)
	}
	for _, c := range controls {
		m := aiactIDPattern.FindStringSubmatch(c.ID)
		if m == nil {
			continue
		}
		var n int
		for _, r := range m[1] {
			n = n*10 + int(r-'0')
		}
		for _, a := range aiactAuthorityArticles {
			if n == a {
				t.Errorf("control %s is on article %d, which binds a notifying authority, a notified body, the AI Office or market surveillance rather than a provider or a deployer", c.ID, n)
			}
		}
	}
}

// TestAIActCoversEachSubjectArea pins the shape of the coverage: the literacy and
// classification articles, the Chapter III provider obligations, the value chain,
// the deployer obligations, the conformity assessment and registration, the
// general-purpose AI model obligations, and the post-market obligations.
//
// A catalogue that silently loses one of these areas would still load, still
// report a coverage percentage, and mean something different from what it
// claims.
func TestAIActCoversEachSubjectArea(t *testing.T) {
	controls, err := catalog.Load("eu_ai_act")
	if err != nil {
		t.Fatalf("Load(eu_ai_act): %v", err)
	}
	covered := map[int]bool{}
	for _, c := range controls {
		if m := aiactIDPattern.FindStringSubmatch(c.ID); m != nil {
			var n int
			for _, r := range m[1] {
				n = n*10 + int(r-'0')
			}
			covered[n] = true
		}
	}

	areas := map[string][]int{
		"literacy and classification":  {4, 5, 6},
		"provider requirements (III)":  {9, 10, 11, 12, 13, 14, 15},
		"provider administration (IV)": {16, 17, 18, 19, 20, 21, 22},
		"value chain (V)":              {23, 24, 25},
		"deployers (VI)":               {26, 27},
		"conformity and registration":  {43, 47, 49},
		"transparency (VII)":           {50},
		"general-purpose AI (VIII)":    {53, 55},
		"post-market (IX)":             {72, 73},
		"penalties (XII)":              {99},
	}

	for area, articles := range areas {
		for _, n := range articles {
			if !covered[n] {
				t.Errorf("%s: article %d (%s) is not covered by any control",
					area, n, aiactArticleTitles[n])
			}
		}
	}
}

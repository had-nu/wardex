// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"regexp"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/catalog"
)

// csfCategories are the 22 Categories of NIST CSWP 29, CSF 2.0, with the names
// Table 1 of the publication gives.
//
// Transcribed rather than read at run time because the publication is not in the
// repository. The point is to catch a catalogue that has drifted from the
// Framework, not to reproduce the Framework.
var csfCategories = map[string]string{
	"GV.OC": "Organizational Context",
	"GV.RM": "Risk Management Strategy",
	"GV.RR": "Roles, Responsibilities, and Authorities",
	"GV.PO": "Policy",
	"GV.OV": "Oversight",
	"GV.SC": "Cybersecurity Supply Chain Risk Management",
	"ID.AM": "Asset Management",
	"ID.RA": "Risk Assessment",
	"ID.IM": "Improvement",
	"PR.AA": "Identity Management, Authentication, and Access Control",
	"PR.AT": "Awareness and Training",
	"PR.DS": "Data Security",
	"PR.PS": "Platform Security",
	"PR.IR": "Technology Infrastructure Resilience",
	"DE.CM": "Continuous Monitoring",
	"DE.AE": "Adverse Event Analysis",
	"RS.MA": "Incident Management",
	"RS.AN": "Incident Analysis",
	"RS.CO": "Incident Response Reporting and Communication",
	"RS.MI": "Incident Mitigation",
	"RC.RP": "Incident Recovery Plan Execution",
	"RC.CO": "Incident Recovery Communication",
}

// csfFunctions maps a Category identifier's prefix to the Function it belongs to.
var csfFunctions = map[string]string{
	"GV": "organizational", "ID": "organizational", "PR": "technological",
	"DE": "technological", "RS": "process", "RC": "process",
}

// TestCSFMatchesTheFrameworkCategories checks the set and the names against
// CSF 2.0.
//
// The previous catalogue carried 31 controls. Nine of them corresponded to no
// Category in the Framework — DE.DP, DE.MI, ID.GV, ID.SC, PR.AW, PR.MA, PR.PM,
// RS.IM and RS.SC — while PR.IR, Technology Infrastructure Resilience, was
// absent. A report naming DE.MI named something the Framework does not contain,
// and the Framework's own infrastructure resilience category had no control at
// all.
func TestCSFMatchesTheFrameworkCategories(t *testing.T) {
	controls, err := catalog.Load("nist_csf")
	if err != nil {
		t.Fatalf("Load(nist_csf): %v", err)
	}

	if len(controls) != len(csfCategories) {
		t.Errorf("catalogue has %d categories, CSF 2.0 has %d", len(controls), len(csfCategories))
	}

	byID := map[string]string{}
	for _, c := range controls {
		if _, dup := byID[c.ID]; dup {
			t.Errorf("category %s appears twice", c.ID)
		}
		byID[c.ID] = c.Name
	}

	for id, name := range csfCategories {
		got, ok := byID[id]
		if !ok {
			t.Errorf("category %s (%s) is missing", id, name)
			continue
		}
		if got != name {
			t.Errorf("category %s is named %q; the Framework names it %q", id, got, name)
		}
	}

	for id := range byID {
		if _, ok := csfCategories[id]; !ok {
			t.Errorf("category %s is in the catalogue but is not a CSF 2.0 Category", id)
		}
	}
}

// TestCSFIdentifiersUseTheFrameworkForm checks the identifier shape. CSF 2.0
// uses mnemonics such as GV.OC, not CSF 1.1 numbering such as GV.1-1, and the
// mnemonic form is what the publication's Table 1 uses.
func TestCSFIdentifiersUseTheFrameworkForm(t *testing.T) {
	shape := regexp.MustCompile(`^[A-Z]{2}\.[A-Z]{2}$`)

	controls, err := catalog.Load("nist_csf")
	if err != nil {
		t.Fatalf("Load(nist_csf): %v", err)
	}
	for _, c := range controls {
		if !shape.MatchString(c.ID) {
			t.Errorf("category %q does not use the Framework's mnemonic form XX.YY", c.ID)
		}
	}
}

// TestCSFEveryFunctionIsPresent checks that all six Functions are represented.
// CSF 2.0 added GOVERN to the five of CSF 1.1, and a catalogue written before
// that addition would have no organizational strategy category at all.
func TestCSFEveryFunctionIsPresent(t *testing.T) {
	controls, err := catalog.Load("nist_csf")
	if err != nil {
		t.Fatalf("Load(nist_csf): %v", err)
	}

	seen := map[string]int{}
	for _, c := range controls {
		seen[c.ID[:2]]++
	}

	for _, fn := range []string{"GV", "ID", "PR", "DE", "RS", "RC"} {
		if seen[fn] == 0 {
			t.Errorf("the %s Function has no category; CSF 2.0 has six Functions", fn)
		}
	}
	if seen["GV"] == 0 {
		t.Error("GOVERN, added in CSF 2.0, is absent")
	}
}

// TestCSFCategoriesFollowTheirFunctionDomain checks a category is filed under
// the domain its Function implies, so GV.RM cannot be reported as technological.
func TestCSFCategoriesFollowTheirFunctionDomain(t *testing.T) {
	controls, err := catalog.Load("nist_csf")
	if err != nil {
		t.Fatalf("Load(nist_csf): %v", err)
	}
	for _, c := range controls {
		want, ok := csfFunctions[c.ID[:2]]
		if !ok {
			t.Errorf("category %s is in an unknown Function", c.ID)
			continue
		}
		if c.Domain != want {
			t.Errorf("category %s (%s) is in domain %q; the %s Function implies %q",
				c.ID, c.Name, c.Domain, c.ID[:2], want)
		}
	}
}

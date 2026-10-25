// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v3/pkg/catalog"
)

// annexATitles are the titles ISO/IEC 27002:2022 gives the 93 Annex A controls.
//
// The list is transcribed here rather than derived at run time because the
// standard is not in the repository. Its purpose is to catch a catalogue that
// has drifted from the standard, not to reproduce the standard: the catalogue
// carries identifiers, not quotations.
//
// Counts per chapter, from the standard: 5 organizational 37, 6 people 8,
// 7 physical 14, 8 technological 34.
var annexATitles = map[string]string{
	"5.1":  "Policies for information security",
	"5.2":  "Information security roles and responsibilities",
	"5.3":  "Segregation of duties",
	"5.4":  "Management responsibilities",
	"5.5":  "Contact with authorities",
	"5.6":  "Contact with special interest groups",
	"5.7":  "Threat intelligence",
	"5.8":  "Information security in project management",
	"5.9":  "Inventory of information and other associated assets",
	"5.10": "Acceptable use of information and other associated assets",
	"5.11": "Return of assets",
	"5.12": "Classification of information",
	"5.13": "Labelling of information",
	"5.14": "Information transfer",
	"5.15": "Access control",
	"5.16": "Identity management",
	"5.17": "Authentication information",
	"5.18": "Access rights",
	"5.19": "Information security in supplier relationships",
	"5.20": "Addressing information security within supplier agreements",
	"5.21": "Managing information security in the ICT supply chain",
	"5.22": "Monitoring, review and change management of supplier services",
	"5.23": "Information security for use of cloud services",
	"5.24": "Information security incident management planning and preparation",
	"5.25": "Assessment and decision on information security events",
	"5.26": "Response to information security incidents",
	"5.27": "Learning from information security incidents",
	"5.28": "Collection of evidence",
	"5.29": "Information security during disruption",
	"5.30": "ICT readiness for business continuity",
	"5.31": "Legal, statutory, regulatory and contractual requirements",
	"5.32": "Intellectual property rights",
	"5.33": "Protection of records",
	"5.34": "Privacy and protection of PII",
	"5.35": "Independent review of information security",
	"5.36": "Compliance with policies, rules and standards for information security",
	"5.37": "Documented operating procedures",
	"6.1":  "Screening",
	"6.2":  "Terms and conditions of employment",
	"6.3":  "Information security awareness, education and training",
	"6.4":  "Disciplinary process",
	"6.5":  "Responsibilities after termination or change of employment",
	"6.6":  "Confidentiality or non-disclosure agreements",
	"6.7":  "Remote working",
	"6.8":  "Information security event reporting",
	"7.1":  "Physical security perimeters",
	"7.2":  "Physical entry",
	"7.3":  "Securing offices, rooms and facilities",
	"7.4":  "Physical security monitoring",
	"7.5":  "Protecting against physical and environmental threats",
	"7.6":  "Working in secure areas",
	"7.7":  "Clear desk and clear screen",
	"7.8":  "Equipment siting and protection",
	"7.9":  "Security of assets off-premises",
	"7.10": "Storage media",
	"7.11": "Supporting utilities",
	"7.12": "Cabling security",
	"7.13": "Equipment maintenance",
	"7.14": "Secure disposal or re-use of equipment",
	"8.1":  "User endpoint devices",
	"8.2":  "Privileged access rights",
	"8.3":  "Information access restriction",
	"8.4":  "Access to source code",
	"8.5":  "Secure authentication",
	"8.6":  "Capacity management",
	"8.7":  "Protection against malware",
	"8.8":  "Management of technical vulnerabilities",
	"8.9":  "Configuration management",
	"8.10": "Information deletion",
	"8.11": "Data masking",
	"8.12": "Data leakage prevention",
	"8.13": "Information backup",
	"8.14": "Redundancy of information processing facilities",
	"8.15": "Logging",
	"8.16": "Monitoring activities",
	"8.17": "Clock synchronization",
	"8.18": "Use of privileged utility programs",
	"8.19": "Installation of software on operational systems",
	"8.20": "Networks security",
	"8.21": "Security of network services",
	"8.22": "Segregation of networks",
	"8.23": "Web filtering",
	"8.24": "Use of cryptography",
	"8.25": "Secure development life cycle",
	"8.26": "Application security requirements",
	"8.27": "Secure system architecture and engineering principles",
	"8.28": "Secure coding",
	"8.29": "Security testing in development and acceptance",
	"8.30": "Outsourced development",
	"8.31": "Separation of development, test and production environments",
	"8.32": "Change management",
	"8.33": "Test information",
	"8.34": "Protection of information systems during audit testing",
}

// isoDomains maps an Annex A control's chapter to the domain this catalogue
// assigns, which follows the standard's own four thematic chapters.
var isoDomains = map[string]string{
	"5": "organizational", "6": "people", "7": "physical", "8": "technological",
}

// TestAnnexAHasTheNinetyThreeControlsOfTheStandard checks the count, the
// identifiers and the titles against the standard.
//
// The previous catalogue carried all 93 identifiers but named 88 of them
// "Control A.x.y", so a reader could not tell what any of them meant and a
// report could not name the obligation it was scoring.
func TestAnnexAHasTheNinetyThreeControlsOfTheStandard(t *testing.T) {
	controls, err := catalog.Load("iso27001")
	if err != nil {
		t.Fatalf("Load(iso27001): %v", err)
	}

	if len(controls) != len(annexATitles) {
		t.Fatalf("catalogue has %d controls, the standard has %d", len(controls), len(annexATitles))
	}

	byID := map[string]string{}
	for _, c := range controls {
		num := strings.TrimPrefix(c.ID, "A.")
		if _, dup := byID[num]; dup {
			t.Errorf("control %s appears twice", c.ID)
		}
		byID[num] = c.Name
	}

	for num, title := range annexATitles {
		got, ok := byID[num]
		if !ok {
			t.Errorf("A.%s (%s) is missing from the catalogue", num, title)
			continue
		}
		if got != title {
			t.Errorf("A.%s is named %q; the standard names it %q", num, got, title)
		}
	}
}

// TestAnnexAHasNoPlaceholderNames catches the specific failure the standard was
// fetched to fix. A generic name is not wrong in the sense of being
// inaccurate, so no other assertion in the suite noticed it.
func TestAnnexAHasNoPlaceholderNames(t *testing.T) {
	placeholder := regexp.MustCompile(`^Control A\.\d+\.\d+$`)

	controls, err := catalog.Load("iso27001")
	if err != nil {
		t.Fatalf("Load(iso27001): %v", err)
	}
	for _, c := range controls {
		if placeholder.MatchString(c.Name) {
			t.Errorf("control %s is named %q, which is the identifier repeated rather than the control", c.ID, c.Name)
		}
	}
}

// TestAnnexADomainsFollowTheStandardChapters checks that a control sits in the
// domain its chapter implies, so a control cannot be reported under
// "technological" when the standard places it among organizational controls.
func TestAnnexADomainsFollowTheStandardChapters(t *testing.T) {
	controls, err := catalog.Load("iso27001")
	if err != nil {
		t.Fatalf("Load(iso27001): %v", err)
	}
	for _, c := range controls {
		num := strings.TrimPrefix(c.ID, "A.")
		chapter, _, found := strings.Cut(num, ".")
		if !found {
			t.Errorf("control %s does not have the A.chapter.sequence form", c.ID)
			continue
		}
		want, ok := isoDomains[chapter]
		if !ok {
			t.Errorf("control %s is in chapter %s, which is not one of the four", c.ID, chapter)
			continue
		}
		if c.Domain != want {
			t.Errorf("control %s (%s) is in domain %q; chapter %s implies %q",
				c.ID, c.Name, c.Domain, chapter, want)
		}
	}
}

// TestAnnexAChapterCounts pins the four chapter counts. A catalogue that lost
// a control from one chapter while keeping the total of 93 would otherwise pass.
func TestAnnexAChapterCounts(t *testing.T) {
	want := map[string]int{"5": 37, "6": 8, "7": 14, "8": 34}

	got := map[string]int{}
	for num := range annexATitles {
		chapter, _, _ := strings.Cut(num, ".")
		got[chapter]++
	}

	for chapter, count := range want {
		if got[chapter] != count {
			t.Errorf("chapter %s has %d controls in this table, the standard has %d", chapter, got[chapter], count)
		}
	}
}

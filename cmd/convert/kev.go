// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package convert

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/had-nu/wardex/pkg/model"
)

// KEVCatalogue represents the CISA Known Exploited Vulnerabilities catalogue.
// Published at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
type KEVCatalogue struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// KEVEntry is a single entry in the CISA KEV catalogue.
type KEVEntry struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"` // RFC 3339 date: "YYYY-MM-DD"
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
	Notes             string `json:"notes"`
}

// LoadKEVCatalogue reads and parses a CISA KEV catalogue JSON file.
// The operator downloads this file; Wardex only reads it (enable, never execute).
func LoadKEVCatalogue(path string) (*KEVCatalogue, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("opening KEV catalogue: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading KEV catalogue: %w", err)
	}

	var catalogue KEVCatalogue
	if err := json.Unmarshal(data, &catalogue); err != nil {
		return nil, fmt.Errorf("parsing KEV catalogue: %w", err)
	}

	return &catalogue, nil
}

// KEVMaxAgeDays is the default warning threshold for catalogue staleness.
const KEVMaxAgeDays = 7

// CheckKEVAge warns if the KEV catalogue file is older than maxAgeDays.
// Returns a non-empty warning string if the file is stale; empty string otherwise.
// Set maxAgeDays to 0 to disable the check.
func CheckKEVAge(path string, maxAgeDays int) string {
	if maxAgeDays <= 0 {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	age := time.Since(info.ModTime())
	if age > time.Duration(maxAgeDays)*24*time.Hour {
		return fmt.Sprintf(
			"[WARN] KEV catalogue is %.0f days old (threshold: %d days). "+
				"Download a fresh copy with:\n"+
				"       curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev-catalogue.json",
			age.Hours()/24, maxAgeDays,
		)
	}
	return ""
}

// CorrelateKEV sets ActivelyExploited, ExploitedSource, and ActivelyExploitedSince
// on each vulnerability that appears in the KEV catalogue.
// CVEs not found in the catalogue are left unchanged.
func CorrelateKEV(vulns []model.Vulnerability, catalogue *KEVCatalogue) []model.Vulnerability {
	kevMap := make(map[string]KEVEntry, len(catalogue.Vulnerabilities))
	for _, entry := range catalogue.Vulnerabilities {
		kevMap[entry.CveID] = entry
	}

	for i, v := range vulns {
		entry, found := kevMap[v.CVEID]
		if !found {
			continue
		}

		vulns[i].ActivelyExploited = true
		vulns[i].ExploitedSource = "cisa-kev"

		// Parse dateAdded from KEV entry (format: "YYYY-MM-DD")
		if t, err := time.Parse("2006-01-02", entry.DateAdded); err == nil {
			vulns[i].ActivelyExploitedSince = t.UTC()
		}
	}

	return vulns
}

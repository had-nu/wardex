package sboms

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

// CycloneDXReport represents the minimal structure of a CycloneDX 1.5 SBOM
// necessary to extract vulnerabilities.
type CycloneDXReport struct {
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities"`
}

type CycloneDXVulnerability struct {
	ID      string `json:"id"`
	Ratings []struct {
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
		Method   string  `json:"method"`
		Vector   string  `json:"vector"`
	} `json:"ratings"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

// ParseCycloneDX reads a CycloneDX 1.5 JSON formatted SBOM and extracts
// the embedded vulnerabilities into the Wardex model.
func ParseCycloneDX(filepath string) ([]model.Vulnerability, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		if _, ok := err.(*fs.PathError); ok {
			return nil, fmt.Errorf("file not found: %s", filepath)
		}
		return nil, fmt.Errorf("failed to read cyclonedx file: %w", err)
	}

	var report CycloneDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse cyclonedx json: %w", err)
	}

	var vulns []model.Vulnerability
	seen := make(map[string]bool)

	for _, v := range report.Vulnerabilities {
		if v.ID == "" {
			continue
		}

		// Find the best CVSS score
		var bestScore float64
		for _, rating := range v.Ratings {
			if rating.Score > bestScore && (rating.Method == "CVSSv3" || rating.Method == "CVSSv31" || rating.Method == "CVSSv4" || rating.Method == "CVSSv2") {
				bestScore = rating.Score
			}
		}

		// Fallback to severity logic if no CVSS score is present
		if bestScore == 0 {
			for _, rating := range v.Ratings {
				switch strings.ToLower(rating.Severity) {
				case "critical":
					bestScore = 9.5
				case "high":
					bestScore = 8.0
				case "medium":
					bestScore = 5.5
				case "low":
					bestScore = 2.0
				}
				if bestScore > 0 {
					break // Break on first found severity
				}
			}
		}

		// Grab the component ref if available
		comp := "unknown-component"
		if len(v.Affects) > 0 {
			// e.g. pkg:npm/lodash@4.17.21
			comp = v.Affects[0].Ref
			if strings.Contains(comp, "?") {
				comp = strings.Split(comp, "?")[0]
			}
		}

		// Deduplicate based on CVE+Component
		key := v.ID + ":" + comp
		if seen[key] {
			continue
		}
		seen[key] = true

		if bestScore > 0 {
			vulns = append(vulns, model.Vulnerability{
				CVEID:     v.ID,
				CVSSBase:  bestScore,
				EPSSScore: 0.05, // SBOMs rarely carry EPSS directly right now; default fallback
				Component: comp,
				Reachable: true, // Conservative default
			})
		}
	}

	return vulns, nil
}

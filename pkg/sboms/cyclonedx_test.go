package sboms

import (
	"os"
	"testing"
)

func TestParseCycloneDX(t *testing.T) {
	// Create a mock CycloneDX 1.5 JSON file containing multiple vulnerabilities
	mockJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"components": [
			{
				"type": "library",
				"bom-ref": "pkg:npm/lodash@4.17.20",
				"name": "lodash"
			}
		],
		"vulnerabilities": [
			{
				"id": "CVE-2021-23337",
				"ratings": [
					{
						"source": {"name": "NVD"},
						"score": 7.5,
						"severity": "high",
						"method": "CVSSv3"
					},
					{
						"source": {"name": "GitHub Inc."},
						"score": 8.0,
						"severity": "high",
						"method": "CVSSv31"
					}
				],
				"affects": [
					{"ref": "pkg:npm/lodash@4.17.20"}
				]
			},
			{
				"id": "CVE-2021-99999",
				"ratings": [
					{
						"severity": "critical"
					}
				],
				"affects": [
					{"ref": "pkg:golang/test@1.0.0"}
				]
			},
			{
				"id": "CVE-2022-12345",
				"ratings": [
					{
						"score": 9.8,
						"severity": "critical",
						"method": "CVSSv3"
					}
				],
				"affects": [
					{"ref": "pkg:npm/express@4.17.1"}
				],
				"analysis": {
					"state": "false_positive",
					"justification": "Code is not reachable in our production environment"
				}
			}
		]
	}`

	tmpFile := "mock-cyclonedx-1.5.json"
	err := os.WriteFile(tmpFile, []byte(mockJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create mock file: %v", err)
	}
	defer os.Remove(tmpFile)

	vulns, err := ParseCycloneDX(tmpFile)
	if err != nil {
		t.Fatalf("ParseCycloneDX failed: %v", err)
	}

	if len(vulns) != 2 {
		t.Errorf("Expected 2 vulnerabilities to be parsed, got %d", len(vulns))
	}

	// Validate the best CVSS score logic (should pick 8.0 over 7.5)
	if vulns[0].CVEID == "CVE-2021-23337" {
		if vulns[0].CVSSBase != 8.0 {
			t.Errorf("Expected best score 8.0, got %f", vulns[0].CVSSBase)
		}
		if vulns[0].Component != "pkg:npm/lodash@4.17.20" {
			t.Errorf("Expected literal component string, got %s", vulns[0].Component)
		}
	} else {
		t.Errorf("First vulnerability was not CVE-2021-23337")
	}

	// Validate the severity fallback logic
	if vulns[1].CVEID == "CVE-2021-99999" {
		if vulns[1].CVSSBase != 9.5 {
			t.Errorf("Severity fallback failed, expected 9.5 for Critical, got %f", vulns[1].CVSSBase)
		}
	}
}

func TestParseSPDX(t *testing.T) {
	tmpFile := "mock-spdx.json"
	os.WriteFile(tmpFile, []byte("{}"), 0644)
	defer os.Remove(tmpFile)

	_, err := ParseSPDX(tmpFile)
	if err == nil {
		t.Errorf("Expected ParseSPDX to natively fail due to lack of VEX support, but it passed")
	}
}

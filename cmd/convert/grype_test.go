// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package convert

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/pkg/model"
	"gopkg.in/yaml.v3"
)

func TestConvertGrype(t *testing.T) {
	mockJSON := `{
	"matches": [
		{
			"vulnerability": {
				"id": "CVE-2023-1234",
				"cvss": [
					{
						"metrics": {
							"baseScore": 8.5
						}
					}
				]
			},
			"artifact": {
				"name": "mock-lib"
			}
		}
	]
}`

	dir := t.TempDir()
	inFile := filepath.Join(dir, "grype.json")
	outFile := filepath.Join(dir, "out.yaml")

	os.WriteFile(inFile, []byte(mockJSON), 0644)

	grypeOutFile = outFile
	defaultEpss = 0.05

	runConvertGrype(nil, []string{inFile})

	outData, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("Expected output YAML, got error: %v", err)
	}

	var parsed struct {
		Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
	}
	if err := yaml.Unmarshal(outData, &parsed); err != nil {
		t.Fatalf("Invalid YAML output: %v", err)
	}

	if len(parsed.Vulnerabilities) != 1 {
		t.Fatalf("Expected 1 vuln, got %d", len(parsed.Vulnerabilities))
	}
	v := parsed.Vulnerabilities[0]
	if v.CVEID != "CVE-2023-1234" {
		t.Errorf("Expected CVE-2023-1234, got %s", v.CVEID)
	}
	if v.CVSSBase != 8.5 {
		t.Errorf("Expected 8.5, got %.1f", v.CVSSBase)
	}
	if v.Component != "mock-lib" {
		t.Errorf("Expected mock-lib, got %s", v.Component)
	}
}

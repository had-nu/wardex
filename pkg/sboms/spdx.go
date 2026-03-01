// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package sboms

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

// SPDXDocument represents the minimal structure of an SPDX 2.3 JSON SBOM.
type SPDXDocument struct {
	Packages []struct {
		SPDXID       string `json:"SPDXID"`
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceType     string `json:"referenceType"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs,omitempty"`
	} `json:"packages"`
}

// ParseSPDX doesn't natively extract vulnerabilities because standard SPDX
// documents (unlike CycloneDX VEX) primarily track components (PURL/CPE)
// instead of embedded CVEs.
//
// In a mature pipeline, this would cross-reference the extracted
// component PURLs against an upstream vulnerability database (like OSV).
// For the scope of Wardex ingestion today, we extract the structural shell
// and throw a strategic NotImplementedError until VEX ingestion (G-17) is built.
func ParseSPDX(filepath string) ([]model.Vulnerability, error) {
	_, err := os.ReadFile(filepath)
	if err != nil {
		if _, ok := err.(*fs.PathError); ok {
			return nil, fmt.Errorf("file not found: %s", filepath)
		}
		return nil, fmt.Errorf("failed to read spdx file: %w", err)
	}

	return nil, fmt.Errorf("SPDX formats track inventory but do not natively embed vulnerabilities. Use CycloneDX or wait for VEX support (G-17)")
}

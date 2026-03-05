// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

// EPSSEnrichment is an individual EPSS score fetched for a CVE.
type EPSSEnrichment struct {
	CVE   string  `yaml:"cve" json:"cve"`
	Score float64 `yaml:"score" json:"score"`
}

// EPSSEnrichmentFile is the structured document that the `wardex enrich` command creates.
type EPSSEnrichmentFile struct {
	Enrichments []EPSSEnrichment `yaml:"enrichments" json:"enrichments"`
	Signature   string           `yaml:"signature" json:"signature"`
	GeneratedAt string           `yaml:"generated_at" json:"generated_at"`
}

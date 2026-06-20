// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package correlator

import (
	"fmt"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// Correlator maps implemented controls to framework requirements.
type Correlator struct {
	Catalog []model.CatalogControl
}

// New creates a new Correlator with the given framework catalog.
func New(catalog []model.CatalogControl) *Correlator {
	return &Correlator{Catalog: catalog}
}

// Correlate maps an array of implemented controls against the catalog.
// Returns a slice of Mappings indicating which controls cover which framework requirements.
func (c *Correlator) Correlate(controls []model.ExistingControl) ([]model.Mapping, error) {
	if len(c.Catalog) == 0 {
		return nil, fmt.Errorf("correlator: empty catalog")
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("correlator: no controls provided")
	}

	var mappings []model.Mapping

	for _, ext := range controls {
		for _, anx := range c.Catalog {
			res := Match(ext, anx)
			if res.Matched {
				mappings = append(mappings, model.Mapping{
					ExistingControlID: ext.ID,
					CatalogControlID:  anx.ID,
					Confidence:        res.Confidence,
					MatchedDomains:    res.MatchedDomains,
					MatchedKeywords:   res.MatchedKeywords,
				})
			}
		}
	}

	return mappings, nil
}

// CorrelateWithConfidence filters mappings by confidence level.
func (c *Correlator) CorrelateWithConfidence(controls []model.ExistingControl, minConfidence string) ([]model.Mapping, error) {
	mappings, err := c.Correlate(controls)
	if err != nil {
		return nil, err
	}
	if minConfidence == "high" {
		filtered := make([]model.Mapping, 0)
		for _, m := range mappings {
			if m.Confidence == "high" {
				filtered = append(filtered, m)
			}
		}
		return filtered, nil
	}
	return mappings, nil
}

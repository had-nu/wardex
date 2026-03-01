// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package analyzer

import (
	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/scorer"
)

type Analyzer struct {
	Catalog  []model.CatalogControl
	Mappings []model.Mapping
	Controls []model.ExistingControl
}

func New(catalog []model.CatalogControl, mappings []model.Mapping, controls []model.ExistingControl) *Analyzer {
	return &Analyzer{
		Catalog:  catalog,
		Mappings: mappings,
		Controls: controls,
	}
}

// Analyze processes mappings and produces coverage findings for each Annex A control.
func (a *Analyzer) Analyze() []model.Finding {
	var findings []model.Finding

	mappingByAnnex := make(map[string][]model.Mapping)
	for _, m := range a.Mappings {
		mappingByAnnex[m.CatalogControlID] = append(mappingByAnnex[m.CatalogControlID], m)
	}

	for _, anx := range a.Catalog {
		maps := mappingByAnnex[anx.ID]
		finalScore := scorer.Score(anx, maps, a.Controls)

		var status model.CoverageStatus
		var reasons []string

		if len(maps) == 0 {
			status = model.StatusGap
			reasons = append(reasons, "Nenhuma correlação encontrada")
		} else {
			status, reasons = EvaluateCoverage(maps, a.Controls)
		}

		finding := model.Finding{
			Control:    anx,
			Status:     status,
			FinalScore: finalScore,
			CoveredBy:  maps,
			GapReasons: reasons,
		}

		findings = append(findings, finding)
	}

	return findings
}

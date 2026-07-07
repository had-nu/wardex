// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package scorer

import (
	"sort"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// Roadmap returns a sorted list of findings that are not fully covered, prioritized by risk/score.
func Roadmap(findings []model.Finding) []model.Finding {
	var roadmap []model.Finding
	for _, f := range findings {
		if f.Status != model.StatusCovered {
			roadmap = append(roadmap, f)
		}
	}

	sort.Slice(roadmap, func(i, j int) bool {
		return roadmap[i].FinalScore > roadmap[j].FinalScore
	})

	return roadmap
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package snapshot

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// Diff computes the variation between the current report and the previous snapshot.
func Diff(current, previous model.GapReport) model.Delta {
	delta := model.Delta{
		SnapshotDate:   previous.Summary.GeneratedAt,
		CoverageChange: current.Summary.GlobalCoverage - previous.Summary.GlobalCoverage,
	}

	prevStatus := make(map[string]model.CoverageStatus)
	for _, f := range previous.Findings {
		prevStatus[f.Control.ID] = f.Status
	}

	for _, curr := range current.Findings {
		ps, exists := prevStatus[curr.Control.ID]
		if !exists {
			fmt.Fprintf(os.Stderr, "[WARN] Control %s not in previous snapshot — skipped in delta\n", curr.Control.ID)
			continue
		}

		if curr.Status == model.StatusCovered && ps != model.StatusCovered {
			delta.NewlyCovered = append(delta.NewlyCovered, curr.Control.ID)
		} else if ps == model.StatusCovered && curr.Status != model.StatusCovered {
			delta.NewGaps = append(delta.NewGaps, curr.Control.ID)
		} else if curr.Status == ps {
			delta.Unchanged++
		}
	}

	currGateLvl := 0
	if current.Gate != nil {
		currGateLvl = current.Gate.GateMaturityLevel
	}

	prevGateLvl := 0
	if previous.Gate != nil {
		prevGateLvl = previous.Gate.GateMaturityLevel
	}

	delta.GateMaturityChange = currGateLvl - prevGateLvl

	return delta
}

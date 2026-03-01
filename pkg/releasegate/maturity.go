// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package releasegate

import "github.com/had-nu/wardex/pkg/model"

// InferMaturityLevel deduces the gate maturity level from defined asset context parameters.
func InferMaturityLevel(ctx model.AssetContext, controls []model.CompensatingControl) int {
	score := 1
	if ctx.InternetFacing {
		score++
	}
	if ctx.RequiresAuth {
		score++
	}
	if len(controls) > 0 {
		score++
	}

	return score
}

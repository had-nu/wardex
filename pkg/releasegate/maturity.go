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

package scorer

import (
	"github.com/had-nu/wardex/pkg/model"
)

// Score calculates the final score for an Annex A control based on
// its base score and the context weight of the implemented controls that cover it.
func Score(annexControl model.AnnexAControl, mappings []model.Mapping, controls []model.ExistingControl) float64 {
	weight := 1.0 // default multiplier

	// If the control is covered by implemented controls, we evaluate the weights
	// Taking the highest context weight to be conservative if multiple controls map
	if len(mappings) > 0 {
		maxWeight := 0.0
		for _, m := range mappings {
			// Find the corresponding ExistingControl
			for _, ec := range controls {
				if ec.ID == m.ExistingControlID {
					if ec.ContextWeight > maxWeight {
						maxWeight = ec.ContextWeight
					}
					break
				}
			}
		}
		if maxWeight > 0.0 {
			weight = maxWeight
		}
	}

	// Clamp the context weight to [0.5, 2.0] per specification
	if weight < 0.5 {
		weight = 0.5
	} else if weight > 2.0 {
		weight = 2.0
	}

	return annexControl.BaseScore * weight
}

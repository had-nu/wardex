package ingestion

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

type jsonExistingControl struct {
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	Description         string           `json:"description"`
	Framework           string           `json:"framework"`
	Domains             []string         `json:"domains"`
	Maturity            int              `json:"maturity"`
	Evidences           []model.Evidence `json:"evidences"`
	ContextWeight       *float64         `json:"context_weight"`
	WeightJustification string           `json:"weight_justification"`
}

type jsonFormat struct {
	Controls []jsonExistingControl `json:"controls"`
}

func loadJSON(path string) ([]model.ExistingControl, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var parsed jsonFormat
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	var controls []model.ExistingControl
	for i, c := range parsed.Controls {
		weight := 1.0
		if c.ContextWeight != nil {
			weight = *c.ContextWeight
		}

		mapped := model.ExistingControl{
			ID:                  c.ID,
			Name:                c.Name,
			Description:         c.Description,
			Framework:           c.Framework,
			Domains:             c.Domains,
			Maturity:            c.Maturity,
			Evidences:           c.Evidences,
			ContextWeight:       weight,
			WeightJustification: c.WeightJustification,
		}

		if err := validateControl(mapped, i); err != nil {
			return nil, err
		}
		controls = append(controls, mapped)
	}

	return controls, nil
}

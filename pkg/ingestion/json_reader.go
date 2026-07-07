// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ingestion

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
)

type jsonExistingControl struct {
	ID                  string             `json:"id"`
	Name                string             `json:"name"`
	Description         string             `json:"description"`
	Framework           string             `json:"framework"`
	Domains             []string           `json:"domains"`
	Maturity            int                `json:"maturity"`
	Layer               model.ControlLayer `json:"layer"`
	Effectiveness       float64            `json:"effectiveness"`
	ReviewRequired      bool               `json:"review_required"`
	Evidences           []model.Evidence   `json:"evidences"`
	ContextWeight       *float64           `json:"context_weight"`
	WeightJustification string             `json:"weight_justification"`
}

type jsonFormat struct {
	Controls []jsonExistingControl `json:"controls"`
}

func loadJSON(path string) ([]model.ExistingControl, error) {
	safePathStr, err := cli.SafePath(path)
	if err != nil {
		return nil, fmt.Errorf("safe path validation failed: %w", err)
	}
	data, err := os.ReadFile(safePathStr) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var parsed jsonFormat
	if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Controls) == 0 {
		// Try root list format if wrapped format fails or is empty
		var rootList []jsonExistingControl
		if err2 := json.Unmarshal(data, &rootList); err2 == nil && len(rootList) > 0 {
			parsed.Controls = rootList
		} else if err != nil {
			return nil, fmt.Errorf("parsing JSON: %w", err)
		}
	}

	var controls []model.ExistingControl
	for i, c := range parsed.Controls {
		weight := 1.0
		if c.ContextWeight != nil {
			weight = *c.ContextWeight
		}

		layer := c.Layer
		if layer == "" {
			layer = model.LayerDocumented
		}

		mapped := model.ExistingControl{
			ID:                  c.ID,
			Name:                c.Name,
			Description:         c.Description,
			Framework:           c.Framework,
			Domains:             c.Domains,
			Maturity:            c.Maturity,
			Layer:               layer,
			Effectiveness:       c.Effectiveness,
			ReviewRequired:      c.ReviewRequired,
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

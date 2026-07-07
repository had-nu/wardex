// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ingestion

import (
	"bytes"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

// yamlExistingControl mirrors ExistingControl to define mapping tags
type yamlExistingControl struct {
	ID                  string             `yaml:"id"`
	Name                string             `yaml:"name"`
	Description         string             `yaml:"description"`
	Framework           string             `yaml:"framework"`
	Domains             []string           `yaml:"domains"`
	Maturity            int                `yaml:"maturity"`
	Layer               model.ControlLayer `yaml:"layer"`
	Effectiveness       float64            `yaml:"effectiveness"`
	ReviewRequired      bool               `yaml:"review_required"`
	Evidences           []model.Evidence   `yaml:"evidences"`
	ContextWeight       *float64           `yaml:"context_weight"`
	WeightJustification string             `yaml:"weight_justification"`
}

type yamlFormat struct {
	Controls []yamlExistingControl `yaml:"controls"`
}

func loadYAML(path string) ([]model.ExistingControl, error) {
	safePathStr, err := cli.SafePath(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(safePathStr) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var parsed yamlFormat
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&parsed); err != nil || len(parsed.Controls) == 0 {
		// Try root list format if wrapped format fails or is empty
		var rootList []yamlExistingControl
		if err2 := yaml.Unmarshal(data, &rootList); err2 == nil && len(rootList) > 0 {
			parsed.Controls = rootList
		} else if err != nil {
			return nil, fmt.Errorf("parsing YAML: %w", err)
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

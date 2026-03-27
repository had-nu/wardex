// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ingestion

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	cwd, _ := os.Getwd()
	safePathStr, err := safePath(cwd, path)
	if err != nil {
		return nil, fmt.Errorf("safe path validation failed: %w", err)
	}
	data, err := os.ReadFile(safePathStr)
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

// safePath prevents path traversal outside the base directory.
func safePath(base, input string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	absInput, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absInput, absBase+string(filepath.Separator)) && absInput != absBase {
		return "", fmt.Errorf("path %q escapes base dir", input)
	}
	return absInput, nil
}

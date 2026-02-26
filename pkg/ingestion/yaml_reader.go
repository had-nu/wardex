package ingestion

import (
	"bytes"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
	"gopkg.in/yaml.v3"
)

// yamlExistingControl mirrors ExistingControl to define mapping tags
type yamlExistingControl struct {
	ID                  string           `yaml:"id"`
	Name                string           `yaml:"name"`
	Description         string           `yaml:"description"`
	Framework           string           `yaml:"framework"`
	Domains             []string         `yaml:"domains"`
	Maturity            int              `yaml:"maturity"`
	Evidences           []model.Evidence `yaml:"evidences"`
	ContextWeight       *float64         `yaml:"context_weight"`
	WeightJustification string           `yaml:"weight_justification"`
}

type yamlFormat struct {
	Controls []yamlExistingControl `yaml:"controls"`
}

func loadYAML(path string) ([]model.ExistingControl, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var parsed yamlFormat
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
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

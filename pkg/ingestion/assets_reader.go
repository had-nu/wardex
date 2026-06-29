// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ingestion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

// LoadAssets loads asset definitions from a YAML or JSON file.
func LoadAssets(path string) ([]model.Asset, error) {
	cwd, _ := os.Getwd()
	safePathStr, err := cli.ValidateInputPath(cwd, path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(safePathStr) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("reading asset file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	var assets []model.Asset

	if ext == ".yaml" || ext == ".yml" {
		var format struct {
			Assets []model.Asset `yaml:"assets"`
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&format); err != nil || len(format.Assets) == 0 {
			// Try root list format
			var rootList []model.Asset
			if err2 := yaml.Unmarshal(data, &rootList); err2 == nil && len(rootList) > 0 {
				assets = rootList
			} else if err != nil {
				return nil, fmt.Errorf("parsing asset YAML: %w", err)
			}
		} else {
			assets = format.Assets
		}
	} else if ext == ".json" {
		var format struct {
			Assets []model.Asset `json:"assets"`
		}
		if err := json.Unmarshal(data, &format); err != nil || len(format.Assets) == 0 {
			// Try root list format
			var rootList []model.Asset
			if err2 := json.Unmarshal(data, &rootList); err2 == nil && len(rootList) > 0 {
				assets = rootList
			} else if err != nil {
				return nil, fmt.Errorf("parsing asset JSON: %w", err)
			}
		} else {
			assets = format.Assets
		}
	} else {
		return nil, fmt.Errorf("unsupported asset file format: %s", ext)
	}

	// Simple validation
	for i, a := range assets {
		if a.ID == "" {
			return nil, fmt.Errorf("asset at index %d missing mandatory 'id'", i)
		}
		if a.Name == "" {
			return nil, fmt.Errorf("asset '%s' missing mandatory 'name'", a.ID)
		}
	}

	return assets, nil
}

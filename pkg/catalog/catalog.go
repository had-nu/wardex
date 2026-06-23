// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog

import (
	"bytes"
	"embed"
	"fmt"

	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var catalogFS embed.FS

// Load loads the requested framework controls from the embedded YAML files.
func Load(framework string) ([]model.CatalogControl, error) {
	var filename string
	switch framework {
	case "iso27001":
		filename = "annex_a.yaml"
	case "soc2":
		filename = "soc2.yaml"
	case "nis2":
		filename = "nis2.yaml"
	case "dora":
		filename = "dora.yaml"
	case "nist_csf":
		filename = "nist_csf.yaml"
	default:
		return nil, fmt.Errorf("framework não suportado: %s. Use: iso27001, soc2, nis2, dora", framework)
	}

	data, err := catalogFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("falha ao ler %s incorporado: %w", filename, err)
	}

	var controls []model.CatalogControl
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	if err := decoder.Decode(&controls); err != nil {
		return nil, fmt.Errorf("falha ao fazer parse de %s: %w", filename, err)
	}

	return controls, nil
}

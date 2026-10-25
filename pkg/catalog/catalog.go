// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package catalog

import (
	"bytes"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/had-nu/wardex/v3/pkg/model"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var catalogFS embed.FS

// entry describes one supported compliance framework.
type entry struct {
	// file is the embedded catalogue filename.
	file string
	// title is the published framework title used in report headings.
	title string
}

// registry is the single source of truth for supported frameworks. Flag help,
// error messages and report titles all derive from it so they cannot disagree.
//
// Scope: Wardex is built for the European market. The frameworks listed here are
// the ones a European regulated entity is asked to evidence: the EU AI Act, the
// Cyber Resilience Act, DORA, the GDPR, NIS2 and two international standards
// used across the EU. SOC 2 was removed for this reason; it is an AICPA
// framework with no standing in EU law, and carrying it implied a scope the
// tool does not serve.
var registry = map[string]entry{
	"iso27001":  {file: "annex_a.yaml", title: "ISO/IEC 27001:2022"},
	"nis2":      {file: "nis2.yaml", title: "NIS2"},
	"dora":      {file: "dora.yaml", title: "DORA"},
	"nist_csf":  {file: "nist_csf.yaml", title: "NIST CSF"},
	"eu_ai_act": {file: "eu_ai_act.yaml", title: "EU AI Act"},
	"gdpr":      {file: "gdpr.yaml", title: "GDPR"},
	"cra":       {file: "cra.yaml", title: "Cyber Resilience Act"},
}

// DisplayName returns the published title for a framework key. It reports false
// when the key is not registered. Callers must not substitute a default title
// for an unknown key: a report that names a framework the run did not use is a
// false statement in a compliance artefact.
func DisplayName(framework string) (string, bool) {
	found, ok := registry[framework]
	return found.title, ok
}

// Keys returns the supported framework keys in stable order.
func Keys() []string {
	keys := make([]string, 0, len(registry))
	for key := range registry {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Load loads the requested framework controls from the embedded YAML files.
func Load(framework string) ([]model.CatalogControl, error) {
	found, ok := registry[framework]
	if !ok {
		return nil, fmt.Errorf("unsupported framework %q: use one of %s", framework, strings.Join(Keys(), ", "))
	}

	data, err := catalogFS.ReadFile(found.file)
	if err != nil {
		return nil, fmt.Errorf("read embedded catalogue %s: %w", found.file, err)
	}

	var controls []model.CatalogControl
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	if err := decoder.Decode(&controls); err != nil {
		return nil, fmt.Errorf("parse catalogue %s: %w", found.file, err)
	}

	// Only annex_a.yaml declares `domains`; the other six catalogues declare a
	// single `domain`. The correlator compares an existing control's declared
	// domains with this field, so a control with an empty list can never match
	// declaratively (high confidence) and falls back to keywords (low
	// confidence). Derive the list from the single domain so every catalogue is
	// matched on the same terms, without duplicating `domain` in the YAML.
	for i := range controls {
		if len(controls[i].Domains) == 0 && controls[i].Domain != "" {
			controls[i].Domains = []string{controls[i].Domain}
		}
	}

	return controls, nil
}

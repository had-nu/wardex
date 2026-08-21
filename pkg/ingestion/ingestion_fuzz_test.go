// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ingestion

import (
	"os"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
)

func FuzzParseYAML(f *testing.F) {
	f.Add([]byte(`controls:
  - id: "CTRL-01"
    name: "Valid"
    maturity: 3
    layer: documented`))
	f.Add([]byte(`controls:
  - id: "CTRL-02"
    name: "Implemented"
    maturity: 5
    layer: implemented`))
	f.Add([]byte(`invalid yaml`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		t.Chdir(dir)
		_ = os.WriteFile("fuzz.yaml", data, 0600)
		controls, err := loadYAML("fuzz.yaml")
		if err != nil {
			return // invalid input is OK
		}
		// Invariant: if parsing succeeded, every control must satisfy the
		// documented shape invariants (id/name non-empty, maturity in 1..5,
		// layer set to a known value).
		for _, c := range controls {
			if c.ID == "" {
				t.Fatalf("parsed control with empty ID")
			}
			if c.Name == "" {
				t.Fatalf("parsed control with empty Name")
			}
			if c.Maturity < 1 || c.Maturity > 5 {
				t.Fatalf("parsed control with invalid maturity: %d", c.Maturity)
			}
			if c.Layer != model.LayerDocumented && c.Layer != model.LayerImplemented {
				t.Fatalf("parsed control with invalid layer: %q", c.Layer)
			}
			if c.ContextWeight <= 0 {
				t.Fatalf("parsed control with non-positive context weight: %f", c.ContextWeight)
			}
		}
	})
}

func FuzzParseJSON(f *testing.F) {
	f.Add([]byte(`{"controls": [{"id": "C1", "name": "Test", "maturity": 3}]}`))
	f.Add([]byte(`{invalid json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		t.Chdir(dir)
		_ = os.WriteFile("fuzz.json", data, 0600)
		_, _ = loadJSON("fuzz.json")
	})
}

func FuzzParseCSV(f *testing.F) {
	f.Add([]byte("id,name,description,maturity,domains,context_weight\n1,Test,Desc,3,tech,1.0"))
	f.Add([]byte("id,name\n1"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		t.Chdir(dir)
		_ = os.WriteFile("fuzz.csv", data, 0600)
		_, _ = loadCSV("fuzz.csv")
	})
}

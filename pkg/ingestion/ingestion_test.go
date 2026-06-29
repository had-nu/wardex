// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ingestion

import (
	"os"
	"testing"
)

func TestIngestionYAML(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	content := `
controls:
  - id: "C1"
    name: "Control 1"
    maturity: 3
    domains: ["access"]
`
	err := os.WriteFile("test.yaml", []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to write mock file: %v", err)
	}

	controls, err := LoadMany([]string{"test.yaml"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
}

func TestIngestionMissingFields(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	content := `
controls:
  - name: "Missing ID"
    maturity: 3
`
	err := os.WriteFile("test.yaml", []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to write mock file: %v", err)
	}

	_, err = LoadMany([]string{"test.yaml"})
	if err == nil {
		t.Fatalf("expected error due to missing mandatory field")
	}
}

func TestIngestionMergeDuplicates(t *testing.T) {
	content1 := `
controls:
  - id: "C1"
    name: "Control 1"
    maturity: 3
`
	content2 := `
controls:
  - id: "C1"
    name: "Control 1 Updated"
    maturity: 4
  - id: "C2"
    name: "Control 2"
    maturity: 2
`
	d := t.TempDir()
	t.Chdir(d)

	err := os.WriteFile("f1.yaml", []byte(content1), 0600)
	if err != nil {
		t.Fatalf("Failed to write mock file f1: %v", err)
	}
	err = os.WriteFile("f2.yaml", []byte(content2), 0600)
	if err != nil {
		t.Fatalf("Failed to write mock file f2: %v", err)
	}

	controls, err := LoadMany([]string{"f1.yaml", "f2.yaml"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 2 {
		t.Fatalf("expected 2 merged controls, got %d", len(controls))
	}
}

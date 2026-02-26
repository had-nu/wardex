package ingestion

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIngestionYAML(t *testing.T) {
	content := `
controls:
  - id: "C1"
    name: "Control 1"
    maturity: 3
    domains: ["access"]
`
	file := filepath.Join(t.TempDir(), "test.yaml")
	os.WriteFile(file, []byte(content), 0644)

	controls, err := LoadMany([]string{file})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
}

func TestIngestionMissingFields(t *testing.T) {
	content := `
controls:
  - name: "Missing ID"
    maturity: 3
`
	file := filepath.Join(t.TempDir(), "test.yaml")
	os.WriteFile(file, []byte(content), 0644)

	_, err := LoadMany([]string{file})
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
	f1 := filepath.Join(d, "f1.yaml")
	f2 := filepath.Join(d, "f2.yaml")

	os.WriteFile(f1, []byte(content1), 0644)
	os.WriteFile(f2, []byte(content2), 0644)

	controls, err := LoadMany([]string{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 2 {
		t.Fatalf("expected 2 merged controls, got %d", len(controls))
	}
}

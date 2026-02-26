package ingestion

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseYAML(f *testing.F) {
	f.Add([]byte(`controls:
  - id: "CTRL-01"
    name: "Valid"
    maturity: 3`))
	f.Add([]byte(`invalid yaml`))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "fuzz.yaml")
		_ = os.WriteFile(path, data, 0644)
		_, _ = loadYAML(path)
	})
}

func FuzzParseJSON(f *testing.F) {
	f.Add([]byte(`{"controls": [{"id": "C1", "name": "Test", "maturity": 3}]}`))
	f.Add([]byte(`{invalid json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "fuzz.json")
		_ = os.WriteFile(path, data, 0644)
		_, _ = loadJSON(path)
	})
}

func FuzzParseCSV(f *testing.F) {
	f.Add([]byte("id,name,description,maturity,domains,context_weight\n1,Test,Desc,3,tech,1.0"))
	f.Add([]byte("id,name\n1"))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "fuzz.csv")
		_ = os.WriteFile(path, data, 0644)
		_, _ = loadCSV(path)
	})
}

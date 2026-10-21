package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPublishedExamplesMatchSchema checks that the files published as
// examples load against the live schema without unknown fields. It is the
// guard-rail that prevents a repeat of the v1.9.1 regression: the documented
// schema diverging from the code schema without detection in CI.
//
// `KnownFields(true)` makes the decoder fail on any key that does not match a
// YAML tag of Config, AssetContext, CompensatingControl or other nested
// structs.
func TestPublishedExamplesMatchSchema(t *testing.T) {
	targets := []struct {
		name string
		path string
	}{
		{"doc example", filepath.Join("..", "doc", "examples", "wardex-config.yaml")},
		{"testdata fixture", filepath.Join("..", "test", "testdata", "wardex-config.yaml")},
	}

	for _, tt := range targets {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("read %s: %v", tt.path, err)
			}

			var cfg Config
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true)
			if err := dec.Decode(&cfg); err != nil {
				t.Fatalf("strict decode of %s: %v\n"+
					"Hint: published example contains a field that does not "+
					"match any yaml tag in Config or its nested structs. "+
					"Update the example to match the live schema, or add the "+
					"missing field to the struct.", tt.path, err)
			}
		})
	}
}

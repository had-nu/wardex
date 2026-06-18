package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPublishedExamplesMatchSchema verifica que os ficheiros publicados como
// exemplo carregam contra o schema vivo sem campos desconhecidos. É a guard-rail
// que impede repetição da regressão de v1.9.1: schema documentado divergir do
// schema do código sem detecção em CI.
//
// `KnownFields(true)` força o decoder a falhar em qualquer chave que não
// corresponda a um yaml tag de Config, AssetContext, CompensatingControl ou
// outras structs nested.
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

package catalog

import (
	"bytes"
	"embed"
	"log"

	"github.com/had-nu/wardex/pkg/model"
	"gopkg.in/yaml.v3"
)

//go:embed annex_a.yaml
var catalogFS embed.FS

// Load loads the ISO 27001 Annex A controls from the embedded YAML file.
func Load() []model.AnnexAControl {
	data, err := catalogFS.ReadFile("annex_a.yaml")
	if err != nil {
		log.Fatalf("failed to read embedded annex_a.yaml: %v", err)
	}

	var controls []model.AnnexAControl
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true) // strict parsing

	if err := decoder.Decode(&controls); err != nil {
		log.Fatalf("failed to parse annex_a.yaml: %v", err)
	}

	return controls
}

package catalog

import (
	"bytes"
	"embed"
	"log"

	"github.com/had-nu/wardex/pkg/model"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var catalogFS embed.FS

// Load loads the requested framework controls from the embedded YAML files.
func Load(framework string) []model.CatalogControl {
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
	default:
		log.Fatalf("unsupported framework: %s", framework)
	}

	data, err := catalogFS.ReadFile(filename)
	if err != nil {
		log.Fatalf("failed to read embedded %s: %v", filename, err)
	}

	var controls []model.CatalogControl
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true) // strict parsing

	if err := decoder.Decode(&controls); err != nil {
		log.Fatalf("failed to parse %s: %v", filename, err)
	}

	return controls
}

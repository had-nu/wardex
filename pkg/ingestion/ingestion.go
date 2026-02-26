package ingestion

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

// Load detects the file format by extension and delegates routing.
func Load(path string) ([]model.ExistingControl, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return loadYAML(path)
	case ".json":
		return loadJSON(path)
	case ".csv":
		return loadCSV(path)
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

// LoadMany loads multiple files and merges the results without duplicates.
func LoadMany(paths []string) ([]model.ExistingControl, error) {
	var allControls []model.ExistingControl
	seen := make(map[string]bool)

	for _, path := range paths {
		controls, err := Load(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", path, err)
		}

		for _, c := range controls {
			if !seen[c.ID] {
				seen[c.ID] = true
				allControls = append(allControls, c)
			}
		}
	}

	return allControls, nil
}

func validateControl(c model.ExistingControl, i int) error {
	if c.ID == "" {
		return fmt.Errorf("control at index %d missing mandatory 'id'", i)
	}
	if c.Name == "" {
		return fmt.Errorf("control '%s' missing mandatory 'name'", c.ID)
	}
	if c.Maturity < 1 || c.Maturity > 5 {
		return fmt.Errorf("control '%s' has invalid maturity %d (must be 1-5)", c.ID, c.Maturity)
	}
	return nil
}

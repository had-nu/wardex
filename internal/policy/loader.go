package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/had-nu/wardex/v2/pkg/cli"
)

// LoadDomain reads and validates a single domain YAML file.
// Returns a validated *DomainFile or a descriptive error — never both.
func LoadDomain(path string) (*DomainFile, error) {
	// Security: prevent path traversal (gosec G304)
	safe, err := cli.ValidateInputPath(".", path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(safe) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("policy: read %q: %w", safe, err)
	}

	var d DomainFile
	if err := yaml.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("policy: parse %q: %w", path, err)
	}

	if err := validateDomain(&d); err != nil {
		return nil, fmt.Errorf("policy: validate %q: %w", path, err)
	}

	return &d, nil
}

// LoadFramework loads and validates all domain YAML files found under dir.
// Files are matched by both *.yml and *.yaml globs; non-YAML files are silently ignored.
func LoadFramework(dir string) ([]*DomainFile, error) {
	var paths []string
	for _, ext := range []string{"*.yml", "*.yaml"} {
		pattern := filepath.Join(dir, ext)
		matched, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("policy: glob %q: %w", dir, err)
		}
		paths = append(paths, matched...)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("policy: no .yml or .yaml files found in %q", dir)
	}

	domains := make([]*DomainFile, 0, len(paths))
	for _, p := range paths {
		d, err := LoadDomain(p)
		if err != nil {
			return nil, err // surface the offending file immediately
		}
		domains = append(domains, d)
	}
	return domains, nil
}

// validateDomain checks required top-level fields and every control's
// ID and status. It does not interpret business rules — only schema rules.
func validateDomain(d *DomainFile) error {
	if d.Framework == "" {
		return fmt.Errorf("missing required field: framework")
	}
	if d.Domain == "" {
		return fmt.Errorf("missing required field: domain")
	}

	for i, c := range d.Controls {
		if c.ID == "" {
			return fmt.Errorf("controls[%d]: missing id", i)
		}
		if c.Title == "" {
			return fmt.Errorf("control %q: missing title", c.ID)
		}
		if !validStatuses[c.Status] {
			return fmt.Errorf("control %q: invalid status %q (must be one of: compliant, partial, non_compliant, not_applicable)", c.ID, c.Status)
		}
	}
	return nil
}

package policy

import "fmt"

// CurrentFormatVersion is the current domain file format version.
// Version 1 is the legacy format: no format_version field (or explicit "1")
// and unknown fields silently ignored at parse time.
const CurrentFormatVersion = 2

// migrationStep upgrades a domain file from one format version to the next.
// Steps run in memory only — source files are never mutated (P4).
type migrationStep func(d *DomainFile) error

// migrations maps each source format version to the step that upgrades it.
// An absent step yields an explicit error: no silent forward-jump.
var migrations = map[int]migrationStep{
	1: migrateV1ToV2,
}

// migrateV1ToV2 is the baseline step from the legacy format. The schema is
// unchanged in this step; it pins the declared version and guards the
// legacy document against structural gaps before it is treated as current.
func migrateV1ToV2(d *DomainFile) error {
	if d.Framework == "" || d.Domain == "" {
		return fmt.Errorf("legacy v1 document missing required fields")
	}
	return nil
}

// Migrate upgrades d in memory from its current FormatVersion to target.
// Each hop runs the declarative step for its source version; a missing step
// returns an error instead of skipping the version.
func Migrate(d *DomainFile, target int) error {
	if d.FormatVersion > target {
		return fmt.Errorf("policy: document format v%d is newer than target v%d", d.FormatVersion, target)
	}
	if d.FormatVersion < 1 {
		return fmt.Errorf("policy: invalid source format v%d", d.FormatVersion)
	}
	for v := d.FormatVersion; v < target; v++ {
		step, ok := migrations[v]
		if !ok {
			return fmt.Errorf("policy: no migration from format v%d to v%d", v, v+1)
		}
		if err := step(d); err != nil {
			return fmt.Errorf("policy: migrate v%d to v%d: %w", v, v+1, err)
		}
		d.FormatVersion = v + 1
	}
	return nil
}

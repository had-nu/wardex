package cpl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/had-nu/wardex/v3/pkg/cli"
)

type LinkStatus string

const (
	StatusOK            LinkStatus = "OK"
	StatusMismatch      LinkStatus = "MISMATCH"
	StatusMissing       LinkStatus = "MISSING"
	StatusSchemaVersion LinkStatus = "SCHEMA_VERSION"
)

type LinkResult struct {
	EntryTimestamp        time.Time  `json:"entry_timestamp"`
	Status                LinkStatus `json:"status"`
	RecordedHash          string     `json:"recorded_hash,omitempty"`
	ComputedHash          string     `json:"computed_hash,omitempty"`
	ConfigFile            string     `json:"config_file,omitempty"`
	RecordedSchemaVersion int        `json:"recorded_schema_version,omitempty"`
}

type linkEntry struct {
	Timestamp        time.Time `json:"ts"`
	ConfigHash       string    `json:"config_hash,omitempty"`
	Event            string    `json:"event"`
	CplSchemaVersion int       `json:"cpl_schema_version,omitempty"`
}

// legacySchemaVersion is the effective schema version of entries written
// before the cpl_schema_version field existed.
const legacySchemaVersion = 1

func VerifyLink(log []byte, configDir string) ([]LinkResult, error) {
	return VerifyLinkWithSchemaVersion(log, configDir, 0)
}

func VerifyLinkWithSchemaVersion(log []byte, configDir string, expectedSchemaVersion int) ([]LinkResult, error) {
	return VerifyLinkWithSchemaVersionWriter(log, configDir, expectedSchemaVersion, os.Stderr)
}

// VerifyLinkWithSchemaVersionWriter is the writer-injectable variant used by
// CLI callers so warnings follow the configured stderr destination.
func VerifyLinkWithSchemaVersionWriter(log []byte, configDir string, expectedSchemaVersion int, warning io.Writer) ([]LinkResult, error) {
	if warning == nil {
		warning = io.Discard
	}
	return verifyLink(log, expectedSchemaVersion, func(e linkEntry) ([]byte, string, bool, error) {
		file := findConfigForTimestamp(configDir, e.Timestamp)
		if file == "" {
			return nil, "", true, nil
		}
		raw, err := cli.ReadFile(file)
		if err != nil {
			return nil, file, true, nil
		}
		return raw, file, false, nil
	}, warning)
}

func VerifyLinkSingle(log []byte, configPath string) ([]LinkResult, error) {
	return VerifyLinkSingleWithSchemaVersion(log, configPath, 0)
}

func VerifyLinkSingleWithSchemaVersion(log []byte, configPath string, expectedSchemaVersion int) ([]LinkResult, error) {
	return VerifyLinkSingleWithSchemaVersionWriter(log, configPath, expectedSchemaVersion, os.Stderr)
}

// VerifyLinkSingleWithSchemaVersionWriter is the writer-injectable variant
// for single-config verification.
func VerifyLinkSingleWithSchemaVersionWriter(log []byte, configPath string, expectedSchemaVersion int, warning io.Writer) ([]LinkResult, error) {
	raw, err := cli.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	if warning == nil {
		warning = io.Discard
	}
	return verifyLink(log, expectedSchemaVersion, func(e linkEntry) ([]byte, string, bool, error) {
		return raw, "", false, nil
	}, warning)
}

func VerifyLinkWithConfig(log []byte, configRaw []byte) ([]LinkResult, error) {
	return VerifyLinkWithConfigAndSchemaVersion(log, configRaw, 0)
}

func VerifyLinkWithConfigAndSchemaVersion(log []byte, configRaw []byte, expectedSchemaVersion int) ([]LinkResult, error) {
	return verifyLink(log, expectedSchemaVersion, func(e linkEntry) ([]byte, string, bool, error) {
		return configRaw, "", false, nil
	}, os.Stderr)
}

// verifyLink is the shared verification core. read resolves the archived
// configuration for an entry: a missing=false, nil-error result carries the
// raw config; missing=true maps to a MISSING status (no archived file).
func verifyLink(log []byte, expectedSchemaVersion int, read func(linkEntry) ([]byte, string, bool, error), warning io.Writer) ([]LinkResult, error) {
	if warning == nil {
		warning = io.Discard
	}
	lines := bytes.Split(bytes.TrimSpace(log), []byte("\n"))
	if len(lines) == 0 {
		return nil, fmt.Errorf("cpl: empty log")
	}

	var results []LinkResult
	for lineNum, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var entry linkEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("cpl: parse entry: %w", err)
		}

		if entry.ConfigHash == "" {
			fmt.Fprintf(warning, "[WARN] CPL entry at line %d has empty config hash - skipped\n", lineNum+1)
			continue
		}

		r := LinkResult{
			EntryTimestamp: entry.Timestamp,
			RecordedHash:   entry.ConfigHash,
		}

		effectiveSchema := entry.CplSchemaVersion
		if effectiveSchema == 0 {
			effectiveSchema = legacySchemaVersion
		}
		if expectedSchemaVersion > 0 {
			r.RecordedSchemaVersion = effectiveSchema
		}

		algo, err := ParseAlgorithmPrefix(entry.ConfigHash)
		if err != nil {
			r.Status = StatusMismatch
			results = append(results, r)
			continue
		}

		raw, file, missing, readErr := read(entry)
		if readErr != nil {
			r.Status = StatusMismatch
			results = append(results, r)
			continue
		}
		if missing {
			r.Status = StatusMissing
			r.ConfigFile = file
			results = append(results, r)
			continue
		}
		r.ConfigFile = file

		computed, err := ComputeConfigHash(raw, algo)
		if err != nil {
			r.Status = StatusMismatch
			results = append(results, r)
			continue
		}
		r.ComputedHash = computed

		switch {
		case computed != entry.ConfigHash:
			r.Status = StatusMismatch
		case expectedSchemaVersion > 0 && effectiveSchema != expectedSchemaVersion:
			r.Status = StatusSchemaVersion
		default:
			r.Status = StatusOK
		}

		results = append(results, r)
	}

	return results, nil
}

func findConfigForTimestamp(configDir string, ts time.Time) string {
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return ""
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".yml" {
			continue
		}
		return filepath.Join(configDir, e.Name())
	}
	return ""
}

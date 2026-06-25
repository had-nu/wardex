package cpl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type LinkStatus string

const (
	StatusOK      LinkStatus = "OK"
	StatusMismatch LinkStatus = "MISMATCH"
	StatusMissing  LinkStatus = "MISSING"
)

type LinkResult struct {
	EntryTimestamp time.Time  `json:"entry_timestamp"`
	Status         LinkStatus `json:"status"`
	RecordedHash   string     `json:"recorded_hash,omitempty"`
	ComputedHash   string     `json:"computed_hash,omitempty"`
	ConfigFile     string     `json:"config_file,omitempty"`
}

type linkEntry struct {
	Timestamp  time.Time `json:"ts"`
	ConfigHash string    `json:"config_hash,omitempty"`
	Event      string    `json:"event"`
}

func VerifyLink(log []byte, configDir string) ([]LinkResult, error) {
	lines := bytes.Split(bytes.TrimSpace(log), []byte("\n"))
	if len(lines) == 0 {
		return nil, fmt.Errorf("cpl: empty log")
	}

	var results []LinkResult
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var entry linkEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("cpl: parse entry: %w", err)
		}

		if entry.ConfigHash == "" {
			continue
		}

		r := LinkResult{
			EntryTimestamp: entry.Timestamp,
			RecordedHash:   entry.ConfigHash,
		}

		algo, err := ParseAlgorithmPrefix(entry.ConfigHash)
		if err != nil {
			r.Status = StatusMismatch
			results = append(results, r)
			continue
		}

		configFile := findConfigForTimestamp(configDir, entry.Timestamp)
		if configFile == "" {
			r.Status = StatusMissing
			results = append(results, r)
			continue
		}
		r.ConfigFile = configFile

		raw, err := os.ReadFile(configFile) // #nosec G304
		if err != nil {
			r.Status = StatusMissing
			results = append(results, r)
			continue
		}

		computed, err := ComputeConfigHash(raw, algo)
		if err != nil {
			r.Status = StatusMismatch
			results = append(results, r)
			continue
		}
		r.ComputedHash = computed

		if computed == entry.ConfigHash {
			r.Status = StatusOK
		} else {
			r.Status = StatusMismatch
		}

		results = append(results, r)
	}

	return results, nil
}

func VerifyLinkSingle(log []byte, configPath string) ([]LinkResult, error) {
	raw, err := os.ReadFile(configPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("cpl: read config: %w", err)
	}

	return VerifyLinkWithConfig(log, raw)
}

func VerifyLinkWithConfig(log []byte, configRaw []byte) ([]LinkResult, error) {
	lines := bytes.Split(bytes.TrimSpace(log), []byte("\n"))
	if len(lines) == 0 {
		return nil, fmt.Errorf("cpl: empty log")
	}

	var results []LinkResult
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var entry linkEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("cpl: parse entry: %w", err)
		}

		if entry.ConfigHash == "" {
			continue
		}

		r := LinkResult{
			EntryTimestamp: entry.Timestamp,
			RecordedHash:   entry.ConfigHash,
		}

		algo, err := ParseAlgorithmPrefix(entry.ConfigHash)
		if err != nil {
			r.Status = StatusMismatch
			results = append(results, r)
			continue
		}

		computed, err := ComputeConfigHash(configRaw, algo)
		if err != nil {
			r.Status = StatusMismatch
			results = append(results, r)
			continue
		}
		r.ComputedHash = computed

		if computed == entry.ConfigHash {
			r.Status = StatusOK
		} else {
			r.Status = StatusMismatch
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

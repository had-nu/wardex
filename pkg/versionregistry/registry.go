// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package versionregistry maintains a derived index of release versions sealed
// in a wardex audit chain. The chain is the source of truth: the registry is a
// cache rebuilt from the chain whenever it is missing, stale or corrupt.
//
// The index file lives next to the audit log as <audit-log>.version-registry.json.
package versionregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/v2/pkg/auditlog"
)

// RegistrySchemaVersion is the schema version of the derived index file.
const RegistrySchemaVersion = 1

// ReleaseInfo describes a single sealed release.
type ReleaseInfo struct {
	Version   string    `json:"version"`
	PolicyRef string    `json:"policy_ref"`
	SealedAt  time.Time `json:"sealed_at"`
	EntryHash string    `json:"entry_hash"`
}

// Registry is the derived index of sealed release versions.
type Registry struct {
	Schema   int                    `json:"schema"`
	LastHash string                 `json:"last_hash,omitempty"`
	Releases map[string]ReleaseInfo `json:"releases"`
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		Schema:   RegistrySchemaVersion,
		Releases: make(map[string]ReleaseInfo),
	}
}

// IndexPath returns the derived index path for an audit log.
func IndexPath(logPath string) string {
	return logPath + ".version-registry.json"
}

// Load reads the registry indexed for an audit log. A missing index yields an
// empty registry; a corrupt or future-schema index is surfaced as an error so
// callers can decide to rebuild from the chain.
func Load(logPath string) (*Registry, error) {
	data, err := os.ReadFile(IndexPath(logPath))
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, fmt.Errorf("versionregistry: read index: %w", err)
	}
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("versionregistry: parse index: %w", err)
	}
	if reg.Schema != RegistrySchemaVersion {
		return nil, fmt.Errorf("versionregistry: index schema %d is not supported", reg.Schema)
	}
	if reg.Releases == nil {
		reg.Releases = make(map[string]ReleaseInfo)
	}
	return &reg, nil
}

// Save writes the registry to its index path for the audit log.
func (r *Registry) Save(logPath string) error {
	if r.Releases == nil {
		r.Releases = make(map[string]ReleaseInfo)
	}
	r.Schema = RegistrySchemaVersion
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("versionregistry: encode index: %w", err)
	}
	if err := os.WriteFile(IndexPath(logPath), data, 0o600); err != nil {
		return fmt.Errorf("versionregistry: write index: %w", err)
	}
	return nil
}

// Has reports whether version has already been sealed.
func (r *Registry) Has(version string) bool {
	_, ok := r.Releases[version]
	return ok
}

// Add records a sealed release and bumps LastHash to the tail of the chain.
func (r *Registry) Add(info ReleaseInfo, lastHash string) {
	if r.Releases == nil {
		r.Releases = make(map[string]ReleaseInfo)
	}
	r.Releases[info.Version] = info
	r.LastHash = lastHash
}

// Rebuild scans the audit chain and collects every release-sealed entry,
// replacing the registry contents. It returns the hash of the last scanned
// line. Entry hashes follow chain semantics: sha256 of the trimmed line.
func (r *Registry) Rebuild(logPath string) (string, error) {
	r.Releases = make(map[string]ReleaseInfo)
	r.LastHash = ""

	lastHash, err := scanReleases(logPath, func(probe releaseProbe, hash string) error {
		r.Releases[probe.ReleaseVersion] = ReleaseInfo{
			Version:   probe.ReleaseVersion,
			PolicyRef: probe.PolicyRef,
			SealedAt:  probe.SealedAt,
			EntryHash: hash,
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	r.LastHash = lastHash
	return lastHash, nil
}

// releaseProbe is the minimal view of an audit entry needed by the index.
type releaseProbe struct {
	ReleaseVersion string    `json:"release_version"`
	PolicyRef      string    `json:"policy_ref"`
	SealedAt       time.Time `json:"ts"`
}

// scanReleases streams the chain once, invoking handler for every entry that
// carries a release_version, and returns the hash of the last scanned line.
func scanReleases(logPath string, handler func(releaseProbe, string) error) (string, error) {
	lastHash := ""
	err := auditlog.ScanFile(logPath, func(line []byte) error {
		hash := hashOf(line)
		lastHash = hash
		var probe releaseProbe
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil
		}
		if probe.ReleaseVersion == "" {
			return nil
		}
		return handler(probe, hash)
	})
	if err != nil {
		return "", fmt.Errorf("versionregistry: rebuild from chain: %w", err)
	}
	return lastHash, nil
}

func hashOf(line []byte) string {
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

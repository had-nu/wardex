// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Manifest represents the cryptographic source-code provenance manifest.
type Manifest struct {
	SchemaVersion        string            `yaml:"schema_version" json:"schema_version"`
	ManifestVersion      string            `yaml:"manifest_version" json:"manifest_version"`
	GitCommit            string            `yaml:"git_commit" json:"git_commit"`
	GitBranch            string            `yaml:"git_branch" json:"git_branch"`
	GeneratedAt          time.Time         `yaml:"generated_at" json:"generated_at"`
	Author               AuthorIdentity    `yaml:"author" json:"author"`
	License              LicenseDecl       `yaml:"license" json:"license"`
	AntiLaunderingNotice string            `yaml:"anti_laundering_notice" json:"anti_laundering_notice"`
	TotalFiles           int               `yaml:"total_files" json:"total_files"`
	RootHash             string            `yaml:"root_hash" json:"root_hash"`
	FileHashes           map[string]string `yaml:"file_hashes" json:"file_hashes"`
	SignedByKeyID        string            `yaml:"signed_by_key_id,omitempty" json:"signed_by_key_id,omitempty"`
	Sig                  string            `yaml:"sig,omitempty" json:"sig,omitempty"`
}

type AuthorIdentity struct {
	Name   string `yaml:"name" json:"name"`
	Email  string `yaml:"email" json:"email"`
	PubKey string `yaml:"pubkey" json:"pubkey"`
	GitHub string `yaml:"github" json:"github"`
}

type LicenseDecl struct {
	SPDX            string `yaml:"spdx" json:"spdx"`
	CopyrightNotice string `yaml:"copyright" json:"copyright"`
}

// CanonicalMessage generates a deterministic JSON representation of the manifest
// with the signature field set to empty. This is used as the signature preimage.
func CanonicalMessage(m *Manifest) ([]byte, error) {
	copyManifest := *m
	copyManifest.Sig = ""

	data, err := json.Marshal(copyManifest)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing manifest: %w", err)
	}
	return data, nil
}

// ComputeRootHash computes the Merkle-like root hash over sorted file hashes.
func ComputeRootHash(fileHashes map[string]string) string {
	var sortedPaths []string
	for p := range fileHashes {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	h := sha256.New()
	for _, p := range sortedPaths {
		h.Write([]byte(p + "|" + fileHashes[p] + "\n"))
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// StripHashPrefix removes the "sha256:" prefix from a hash string.
func StripHashPrefix(hash string) string {
	return strings.TrimPrefix(hash, "sha256:")
}

// GenerateManifest walks the directory baseDir, computes file hashes, and constructs the manifest.
func GenerateManifest(baseDir string, includes, excludes []string, manifestVersion, commit, branch string, author AuthorIdentity, license LicenseDecl, notice string) (*Manifest, error) {
	fileHashes := make(map[string]string)

	excludeMap := make(map[string]bool)
	for _, e := range excludes {
		excludeMap[e] = true
	}

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			name := info.Name()
			if excludeMap[name] || (strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			return nil
		}

		for _, e := range excludes {
			if strings.Contains(relPath, e) {
				return nil
			}
		}

		if len(includes) > 0 {
			matched := false
			for _, pattern := range includes {
				if m, _ := filepath.Match(pattern, filepath.Base(path)); m {
					matched = true
					break
				}
				if m, _ := filepath.Match(pattern, relPath); m {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}

		fileHashes[relPath] = fmt.Sprintf("sha256:%x", h.Sum(nil))
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking files: %w", err)
	}

	rootHash := ComputeRootHash(fileHashes)

	return &Manifest{
		SchemaVersion:        "1.0",
		ManifestVersion:      manifestVersion,
		GitCommit:            commit,
		GitBranch:            branch,
		GeneratedAt:          time.Now().UTC().Truncate(time.Second),
		Author:               author,
		License:              license,
		AntiLaunderingNotice: notice,
		TotalFiles:           len(fileHashes),
		RootHash:             rootHash,
		FileHashes:           fileHashes,
	}, nil
}

// Sign signs the manifest using the provided Ed25519 private key.
func (m *Manifest) Sign(privKey ed25519.PrivateKey, keyID string) error {
	m.SignedByKeyID = keyID
	msg, err := CanonicalMessage(m)
	if err != nil {
		return err
	}

	sigBytes := ed25519.Sign(privKey, msg)
	m.Sig = "ed25519sig:" + base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// Verify checks the Ed25519 signature of the manifest and validates the integrity of all listed files.
func (m *Manifest) Verify(baseDir string) error {
	if m.Sig == "" {
		return fmt.Errorf("manifest is unsigned")
	}

	if !strings.HasPrefix(m.Author.PubKey, "ed25519:") {
		return fmt.Errorf("invalid author public key prefix")
	}
	pubKeyB64 := strings.TrimPrefix(m.Author.PubKey, "ed25519:")
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	if !strings.HasPrefix(m.Sig, "ed25519sig:") {
		return fmt.Errorf("invalid signature prefix")
	}
	sigB64 := strings.TrimPrefix(m.Sig, "ed25519sig:")
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	msg, err := CanonicalMessage(m)
	if err != nil {
		return fmt.Errorf("generating canonical message: %w", err)
	}

	if !ed25519.Verify(pubKey, msg, sigBytes) {
		return fmt.Errorf("invalid Ed25519 signature: manifest has been altered")
	}

	var sortedPaths []string
	for p := range m.FileHashes {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	var missingFiles []string
	var mismatchFiles []string

	for _, relPath := range sortedPaths {
		absPath := filepath.Join(baseDir, relPath)
		f, err := os.Open(absPath)
		if err != nil {
			missingFiles = append(missingFiles, relPath)
			continue
		}

		fh := sha256.New()
		_, err = io.Copy(fh, f)
		f.Close()
		if err != nil {
			mismatchFiles = append(mismatchFiles, relPath)
			continue
		}

		currentHash := fmt.Sprintf("sha256:%x", fh.Sum(nil))
		expectedHash := m.FileHashes[relPath]
		if currentHash != expectedHash {
			mismatchFiles = append(mismatchFiles, relPath)
		}
	}

	if len(missingFiles) > 0 || len(mismatchFiles) > 0 {
		var errMsg []string
		if len(missingFiles) > 0 {
			errMsg = append(errMsg, fmt.Sprintf("missing files: %v", missingFiles))
		}
		if len(mismatchFiles) > 0 {
			errMsg = append(errMsg, fmt.Sprintf("modified files: %v", mismatchFiles))
		}
		return fmt.Errorf("file integrity verification failed: %s", strings.Join(errMsg, "; "))
	}

	recalcRootHash := ComputeRootHash(m.FileHashes)
	if recalcRootHash != m.RootHash {
		return fmt.Errorf("root hash mismatch: got %s, calculated %s", m.RootHash, recalcRootHash)
	}

	return nil
}

// LoadManifest reads and parses a YAML provenance manifest.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing YAML manifest: %w", err)
	}
	return &m, nil
}

// SaveManifest serializes and writes the manifest to a file.
func SaveManifest(path string, m *Manifest) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshaling manifest to YAML: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

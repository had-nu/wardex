package manifest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/immutable-provenance/manifest"
)

func setupTestDir(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "provenance-test-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}

	// Create test files
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("writing main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("AGPL-3.0"), 0644); err != nil {
		t.Fatalf("writing LICENSE: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("ignore me"), 0644); err != nil {
		t.Fatalf("writing ignored.txt: %v", err)
	}

	return dir, func() {
		os.RemoveAll(dir)
	}
}

func TestGenerateAndVerify(t *testing.T) {
	dir, cleanup := setupTestDir(t)
	defer cleanup()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}

	author := manifest.AuthorIdentity{
		Name:   "André Gustavo",
		Email:  "andre@test.com",
		PubKey: "ed25519:" + base64.StdEncoding.EncodeToString(pub),
		GitHub: "had-nu",
	}

	license := manifest.LicenseDecl{
		SPDX:            "AGPL-3.0",
		CopyrightNotice: "Copyright 2026",
	}

	includes := []string{"*.go", "LICENSE"}
	excludes := []string{"ignored.txt"}

	m, err := manifest.GenerateManifest(dir, includes, excludes, "v1.0.0", "abc1234", "main", author, license, "Notice")
	if err != nil {
		t.Fatalf("generating manifest: %v", err)
	}

	if m.TotalFiles != 2 {
		t.Errorf("expected 2 files, got %d", m.TotalFiles)
	}

	if _, exists := m.FileHashes["main.go"]; !exists {
		t.Error("expected main.go in file hashes")
	}

	if _, exists := m.FileHashes["ignored.txt"]; exists {
		t.Error("ignored.txt should be excluded")
	}

	// Sign the manifest
	err = m.Sign(priv, "test-key-01")
	if err != nil {
		t.Fatalf("signing manifest: %v", err)
	}

	// Verify the manifest
	err = m.Verify(dir)
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestVerifyTamperedFile(t *testing.T) {
	dir, cleanup := setupTestDir(t)
	defer cleanup()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}

	author := manifest.AuthorIdentity{
		Name:   "André Gustavo",
		Email:  "andre@test.com",
		PubKey: "ed25519:" + base64.StdEncoding.EncodeToString(pub),
		GitHub: "had-nu",
	}

	m, err := manifest.GenerateManifest(dir, []string{"*.go"}, nil, "v1.0.0", "abc1234", "main", author, manifest.LicenseDecl{}, "")
	if err != nil {
		t.Fatalf("generating manifest: %v", err)
	}

	err = m.Sign(priv, "test-key-01")
	if err != nil {
		t.Fatalf("signing manifest: %v", err)
	}

	// Modify main.go to simulate tampering
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() { /* altered */ }\n"), 0644); err != nil {
		t.Fatalf("tampering main.go: %v", err)
	}

	err = m.Verify(dir)
	if err == nil {
		t.Error("expected verification to fail after file tampering, but it succeeded")
	}
}

func TestVerifyTamperedManifest(t *testing.T) {
	dir, cleanup := setupTestDir(t)
	defer cleanup()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}

	author := manifest.AuthorIdentity{
		Name:   "André Gustavo",
		Email:  "andre@test.com",
		PubKey: "ed25519:" + base64.StdEncoding.EncodeToString(pub),
		GitHub: "had-nu",
	}

	m, err := manifest.GenerateManifest(dir, []string{"*.go"}, nil, "v1.0.0", "abc1234", "main", author, manifest.LicenseDecl{}, "")
	if err != nil {
		t.Fatalf("generating manifest: %v", err)
	}

	err = m.Sign(priv, "test-key-01")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Tamper with the manifest metadata itself (e.g. change version)
	m.ManifestVersion = "v2.0.0"

	err = m.Verify(dir)
	if err == nil {
		t.Error("expected verification to fail after manifest metadata alteration, but it succeeded")
	}
}

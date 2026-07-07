// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// PubKeyPrefix is the canonical prefix for ed25519 public keys in the trust store.
	PubKeyPrefix = "ed25519:"
	// SigPrefix is the canonical prefix for ed25519 signatures.
	SigPrefix = "ed25519sig:"
)

// GenerateKeypair creates an ed25519 keypair and writes it to disk.
// The private key is written with mode 0400; the public key with mode 0644.
// Returns the public key bytes for convenience.
func GenerateKeypair(outPath string, force bool) (ed25519.PublicKey, error) {
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("keygen: create directory %q: %w", dir, err)
	}

	if _, err := os.Stat(outPath); err == nil && !force {
		return nil, fmt.Errorf("keygen: %q already exists — use --force to overwrite", outPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: generate key: %w", err)
	}

	privEncoded := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(outPath, []byte(privEncoded), 0400); err != nil {
		return nil, fmt.Errorf("keygen: write private key: %w", err)
	}

	pubPath := outPath + ".pub"
	pubEncoded := PubKeyPrefix + base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(pubPath, []byte(pubEncoded), 0644); err != nil { // #nosec G306 -- public key, world-readable by design
		return nil, fmt.Errorf("keygen: write public key: %w", err)
	}

	return pub, nil
}

// LoadPrivateKey reads and validates a private key from disk.
// Rejects files with permissions more open than 0600 (same behaviour as openssh).
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	if err := enforceKeyringPermissions(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("keyring: read %q: %w", path, err)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("keyring: decode private key: %w", err)
	}

	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("keyring: invalid private key size: got %d, want %d", len(decoded), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(decoded), nil
}

// LoadPublicKeyFile reads a public key from a .pub file.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("keyring: read public key %q: %w", path, err)
	}
	return DecodePublicKey(strings.TrimSpace(string(data)))
}

// DecodePublicKey parses a "ed25519:<base64>" string into an ed25519.PublicKey.
func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(encoded, PubKeyPrefix) {
		return nil, fmt.Errorf("keyring: public key must start with %q", PubKeyPrefix)
	}
	b64 := strings.TrimPrefix(encoded, PubKeyPrefix)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("keyring: decode public key base64: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("keyring: invalid public key size: got %d, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

// EncodePublicKey formats an ed25519.PublicKey as "ed25519:<base64>".
func EncodePublicKey(pub ed25519.PublicKey) string {
	return PubKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// Sign signs a message with the private key and returns "ed25519sig:<base64>".
func Sign(priv ed25519.PrivateKey, message []byte) string {
	sig := ed25519.Sign(priv, message)
	return SigPrefix + base64.StdEncoding.EncodeToString(sig)
}

// Verify checks an "ed25519sig:<base64>" signature against a message and public key.
func Verify(pub ed25519.PublicKey, message []byte, sigEncoded string) error {
	if !strings.HasPrefix(sigEncoded, SigPrefix) {
		return fmt.Errorf("verify: signature must start with %q", SigPrefix)
	}
	b64 := strings.TrimPrefix(sigEncoded, SigPrefix)
	sigBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("verify: decode signature base64: %w", err)
	}
	if !ed25519.Verify(pub, message, sigBytes) {
		return fmt.Errorf("verify: signature invalid — data may have been tampered with")
	}
	return nil
}

// enforceKeyringPermissions rejects keys with permissions more open than 0600.
// Same behaviour as openssh.
func enforceKeyringPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("keyring: stat %q: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode > 0600 {
		return fmt.Errorf(
			"keyring: %q has permissions %04o — must be 0400 or 0600\n"+
				"Fix: chmod 400 %s",
			path, mode, path,
		)
	}
	return nil
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust_test

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/trust"
)

func assertKeyMatches(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	if got := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey); !got.Equal(pub) {
		t.Fatal("decrypted private key does not match the generated public key")
	}
}

const envelopePassphrase = "wardex-test-envelope-passphrase"

func TestLoadEncryptedEnvelopeViaEnv(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin.wex")

	pub, err := trust.GenerateKeypairEncrypted(keyPath, false, envelopePassphrase)
	if err != nil {
		t.Fatalf("generate encrypted keypair: %v", err)
	}

	// Plain LoadPrivateKey without env must refuse the envelope.
	if _, err := trust.LoadPrivateKey(keyPath); err == nil {
		t.Fatal("encrypted envelope without passphrase must fail")
	}

	t.Setenv("WARDEX_KEY_PASSPHRASE", envelopePassphrase)
	priv, err := trust.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("load via env: %v", err)
	}
	defer zeroize(priv)
	assertKeyMatches(t, priv, pub)

	// Wrong passphrase → generic encrypted-key error, no oracle.
	t.Setenv("WARDEX_KEY_PASSPHRASE", "wrong")
	if _, err := trust.LoadPrivateKey(keyPath); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
}

func TestLoadPrivateKeyWithExplicitPassphrase(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin.wex")

	pub, err := trust.GenerateKeypairEncrypted(keyPath, false, envelopePassphrase)
	if err != nil {
		t.Fatalf("generate encrypted keypair: %v", err)
	}

	priv, err := trust.LoadPrivateKeyWithPassphrase(keyPath, " "+envelopePassphrase+" ")
	if err != nil {
		t.Fatalf("load with explicit passphrase: %v", err)
	}
	defer zeroize(priv)
	assertKeyMatches(t, priv, pub)
}

func TestLoadLegacyPlaintextKeyStillWorks(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "legacy.wex")

	pub, err := trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	// Even with a passphrase set, a plaintext key must load unchanged (P2).
	t.Setenv("WARDEX_KEY_PASSPHRASE", envelopePassphrase)
	priv, err := trust.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("legacy plaintext load failed: %v", err)
	}
	defer zeroize(priv)
	assertKeyMatches(t, priv, pub)
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/trust"
)


func testKeyPath(t *testing.T) string {
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "test.key")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privEncoded := hex.EncodeToString(priv)
	if err := os.WriteFile(keyPath, []byte(privEncoded), 0600); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

func TestGenerateKeypair_Force(t *testing.T) {
	var err error
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "keyring.wex")

	// First generation
	pub1, err := trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatal(err)
	}

	// Second generation without force should fail
	_, err = trust.GenerateKeypair(keyPath, false)
	if err == nil {
		t.Fatal("expected error for existing file without force")
	}

	// With force should succeed - need to remove the read-only file first
	os.Remove(keyPath)
	pub2, err := trust.GenerateKeypair(keyPath, true)
	if err != nil {
		t.Fatal(err)
	}

	// Keys should be different
	if bytes.Equal(pub1, pub2) {
		t.Fatal("expected different keys on force regenerate")
	}
}

func TestGenerateKeypair_Permissions(t *testing.T) {
	var err error
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "keyring.wex")

	_, err = trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Errorf("expected mode 0400, got %04o", info.Mode().Perm())
	}

	pubPath := keyPath + ".pub"
	info, err = os.Stat(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected public key mode 0644, got %04o", info.Mode().Perm())
	}
}

func TestLoadPrivateKey_InvalidPermissions(t *testing.T) {
	var err error
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "keyring.wex")

	_, err = trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatal(err)
	}

	// Mess up permissions
	err = os.Chmod(keyPath, 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = trust.LoadPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error for 0644 permissions")
	}
	if !strings.Contains(err.Error(), "must be 0400 or 0600") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadPrivateKey_InvalidKey(t *testing.T) {
	var err error
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "invalid.key")
	os.WriteFile(keyPath, []byte("not a valid key"), 0400)

	_, err = trust.LoadPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
	if !strings.Contains(err.Error(), "invalid private key size") && !strings.Contains(err.Error(), "decode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadPrivateKey_WrongSize(t *testing.T) {
	var err error
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "wrong.key")
	os.WriteFile(keyPath, []byte("0123456789abcdef"), 0400)

	_, err = trust.LoadPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestLoadPublicKeyFile(t *testing.T) {
	var err error
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "key.wex")
	pubPath := filepath.Join(tmp, "key.wex.pub")

	// Generate a key first
	_, err = trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatal(err)
	}

	_, err = trust.LoadPublicKeyFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodePublicKey_Valid(t *testing.T) {
	var err error
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	pubEncoded := "ed25519:" + base64.StdEncoding.EncodeToString(pub)
	decoded, err := trust.DecodePublicKey(pubEncoded)
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid signature to test verification
	msg := []byte("test")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(decoded, msg, sig) {
		t.Fatal("decoded key should verify")
	}
}

func TestDecodePublicKey_InvalidPrefix(t *testing.T) {
	var err error
	_, err = trust.DecodePublicKey("invalid:key")
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
	if !strings.Contains(err.Error(), "ed25519:") {
		t.Fatalf("expected prefix error, got: %v", err)
	}
}

func TestDecodePublicKey_InvalidBase64(t *testing.T) {
	var err error
	_, err = trust.DecodePublicKey("ed25519:notvalidbase64!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodePublicKey_WrongSize(t *testing.T) {
	var err error
	invalid := "ed25519:" + base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = trust.DecodePublicKey(invalid)
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestVerify_Valid(t *testing.T) {
	var err error
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubEncoded := "ed25519:" + base64.StdEncoding.EncodeToString(pub)
	decodedPub, err := trust.DecodePublicKey(pubEncoded)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	sigEncoded := "ed25519sig:" + base64.StdEncoding.EncodeToString(sig)

	err = trust.Verify(decodedPub, []byte("test message"), sigEncoded)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	sigEncoded := "ed25519sig:" + base64.StdEncoding.EncodeToString(make([]byte, 64))

	err := trust.Verify(pub, []byte("test"), sigEncoded)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestVerify_InvalidPrefix(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	err := trust.Verify(pub, []byte("test"), "invalid:prefix")
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
	if !strings.Contains(err.Error(), "must start with") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerify_InvalidBase64(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	err := trust.Verify(pub, []byte("test"), "ed25519sig:notvalidbase64!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestEnforceKeyringPermissions_PrivateKey(t *testing.T) {
	var err error
	tmp := testDir(t)
	keyPath := filepath.Join(tmp, "keyring.wex")

	_, err = trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatal(err)
	}

	// Should pass with 0400
	err = trust.EnforceKeyringPermissions(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Change to 0600 - should still pass
	os.Chmod(keyPath, 0600)
	err = trust.EnforceKeyringPermissions(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Change to 0644 - should fail
	os.Chmod(keyPath, 0644)
	err = trust.EnforceKeyringPermissions(keyPath)
	if err == nil {
		t.Fatal("expected error for 0644 permissions")
	}
	if !strings.Contains(err.Error(), "must be 0400 or 0600") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnforceKeyringPermissions_Nonexistent(t *testing.T) {
	var err error
	err = trust.EnforceKeyringPermissions("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Fuzz tests

func FuzzDecodePublicKey(f *testing.F) {
	f.Add("ed25519:ABCDEF")
	f.Add("invalid:key")
	f.Add("ed25519:!!!!")

	f.Fuzz(func(t *testing.T, data string) {
		trust.DecodePublicKey(data)
	})
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte("test"))
	f.Add([]byte(""))

f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ed25519.GenerateKey(rand.Reader)
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), data)
		sigEncoded := "ed25519sig:" + hex.EncodeToString(sig)
		trust.Verify(ed25519.PublicKey(make([]byte, 32)), data, sigEncoded)
	})
}

func FuzzEnforceKeyringPermissions(f *testing.F) {
	f.Add([]byte("test"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.key")
		os.WriteFile(path, data, 0400)
		trust.EnforceKeyringPermissions(path)
	})
}
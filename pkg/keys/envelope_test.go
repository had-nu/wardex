// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package keys_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/keys"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

const pass = "correct horse battery staple"

func TestEncryptDecryptRoundtrip(t *testing.T) {
	priv := testKey(t)
	env, err := keys.Encrypt(priv, pass, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := keys.Decrypt(env, pass)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	defer keys.Zeroize(got)
	if !priv.Equal(got) {
		t.Fatal("roundtrip produced a different private key")
	}
	if keys.IsEnvelope(env) {
		t.Error("JSON envelope bytes must not carry the magic header")
	}
}

func TestWrongPassphraseRejectedNoOracle(t *testing.T) {
	priv := testKey(t)
	env, err := keys.Encrypt(priv, pass, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = keys.Decrypt(env, pass+"-wrong")
	if err == nil {
		t.Fatal("wrong passphrase must fail")
	}
	if !errors.Is(err, keys.ErrDecryptionFailed) {
		t.Errorf("wrong passphrase error must be the generic sentinel, got %v", err)
	}
}

func TestCorruptPayloadSameError(t *testing.T) {
	priv := testKey(t)
	env, err := keys.Encrypt(priv, pass, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tampered := strings.Replace(string(env), `"aes-256-gcm"`, `"aes-256-gcs"`, 1)
	_, err = keys.Decrypt([]byte(tampered), pass)
	if !errors.Is(err, keys.ErrDecryptionFailed) {
		t.Errorf("corrupt envelope must map to the generic sentinel, got %v", err)
	}
}

func TestFutureVersionControlledError(t *testing.T) {
	priv := testKey(t)
	env, err := keys.Encrypt(priv, pass, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	future := strings.Replace(string(env), `"version":1`, `"version":2`, 1)
	_, err = keys.Decrypt([]byte(future), pass)
	if !errors.Is(err, keys.ErrUnsupportedVersion) {
		t.Errorf("future envelope must return ErrUnsupportedVersion, got %v", err)
	}
}

func TestFileMagicRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")
	priv := testKey(t)

	if err := keys.WriteEncryptedFile(path, priv, pass); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !keys.IsEnvelope(data) {
		t.Fatal("file must carry the magic header")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0400 {
		t.Errorf("key file mode = %04o, want 0400", perm)
	}

	got, err := keys.ReadEncryptedFile(path, pass)
	if err != nil {
		t.Fatalf("read+decrypt: %v", err)
	}
	defer keys.Zeroize(got)
	if !priv.Equal(got) {
		t.Fatal("file roundtrip produced a different private key")
	}
}

func TestReadPlaintextFileFailsAsNotEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")
	if err := os.WriteFile(path, []byte("oWRkYzQ7LpL8+q8="), 0400); err != nil {
		t.Fatalf("write: %v", err)
	}
	if keys.IsEnvelope(nil) {
		t.Error("empty data must not look like an envelope")
	}
	if _, err := keys.ReadEncryptedFile(path, pass); !errors.Is(err, keys.ErrNotEnvelope) {
		t.Errorf("plaintext file through envelope reader must be ErrNotEnvelope, got %v", err)
	}
}

func TestCustomParamsAllowed(t *testing.T) {
	priv := testKey(t)
	p := keys.DefaultParams()
	p.T = 1
	p.M = 8 * 1024 // 8 MiB, fast profile for tests
	env, err := keys.Encrypt(priv, pass, &p)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := keys.Decrypt(env, pass)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	defer keys.Zeroize(got)
	if !priv.Equal(got) {
		t.Fatal("roundtrip mismatch with custom params")
	}
}

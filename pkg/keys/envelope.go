// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package keys implements the opt-in encrypted envelope (L6) for private keys
// at rest. The envelope follows the store-cipher pattern: Argon2id derivation
// yields a cipher key and a separate verification key, so a wrong passphrase
// is rejected before any authenticated decryption is attempted (no padding
// oracle). The envelope is versioned so KDF/cipher migration in the future
// does not break existing files.
package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// FileMagic is the file-level header that identifies an encrypted envelope.
// Files without it are treated as legacy plaintext keys (P2 — kept working).
const FileMagic = "WARDEX-KEY-V1\n"

// Envelope format constants (v1).
const (
	EnvelopeVersion    = 1
	KDFNameArgon2ID    = "argon2id"
	CipherAES256GCM    = "aes-256-gcm"
	KeyTypeED25519     = "ed25519"
	saltLenBytes       = 16
	nonceLenBytes      = 12
	verificationTagLen = 32
	derivedKeyLen      = 64 // cipher key (32) + verification key (32)
)

// Default KDF parameters (OWASP-aligned Argon2id profile).
const (
	DefaultKDFMemoryKiB = 64 * 1024
	DefaultKDFTime      = 3
	DefaultKDFParallel  = 1
)

// Sentinel errors. ErrDecryptionFailed is intentionally generic: it is
// returned both for a wrong passphrase and for a corrupt payload so the two
// cannot be distinguished (no oracle).
var (
	ErrNotEnvelope        = errors.New("keys: not an encrypted envelope")
	ErrUnsupportedVersion = errors.New("keys: unsupported envelope version")
	ErrDecryptionFailed   = errors.New("keys: decryption failed (wrong passphrase or corrupt payload)")
)

// KDFParams carries the Argon2id cost parameters (m in KiB).
type KDFParams struct {
	T uint32 `json:"t"`
	M uint32 `json:"m"`
	P uint8  `json:"p"`
}

// DefaultParams mirrors the package defaults and is safe to mutate safely
// (the caller may adjust before encrypting).
func DefaultParams() KDFParams {
	return KDFParams{T: DefaultKDFTime, M: DefaultKDFMemoryKiB, P: DefaultKDFParallel}
}

// Envelope is the versioned JSON representation of an encrypted private key.
type Envelope struct {
	Version         int       `json:"version"`
	KDF             string    `json:"kdf"`
	KDFSalt         string    `json:"kdf_salt"`
	KDFParams       KDFParams `json:"kdf_params"`
	Cipher          string    `json:"cipher"`
	Nonce           string    `json:"nonce"`
	VerificationTag string    `json:"verification_tag"`
	KeyType         string    `json:"key_type"`
	Payload         string    `json:"payload"`
}

type keyPayload struct {
	KeyType    string `json:"key_type"`
	PrivateKey string `json:"private_key"`
}

// Encrypt seals an ed25519 private key into a JSON envelope. params may be
// nil to select DefaultParams. The returned bytes contain no magic header;
// use WriteEncryptedFile for the file-level format.
func Encrypt(priv ed25519.PrivateKey, passphrase string, params *KDFParams) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("keys: invalid private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if params == nil {
		p := DefaultParams()
		params = &p
	}
	if params.M == 0 || params.T == 0 || params.P == 0 {
		return nil, errors.New("keys: zero KDF parameters are not allowed")
	}

	salt := make([]byte, saltLenBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("keys: salt: %w", err)
	}
	nonce := make([]byte, nonceLenBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keys: nonce: %w", err)
	}

	env, err := seal(priv, passphrase, salt, nonce, params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

func seal(priv ed25519.PrivateKey, passphrase string, salt, nonce []byte, params *KDFParams) (*Envelope, error) {
	pl, err := json.Marshal(keyPayload{
		KeyType:    KeyTypeED25519,
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	})
	if err != nil {
		return nil, fmt.Errorf("keys: payload: %w", err)
	}

	block, err := aes.NewCipher(deriveCipherKey(passphrase, salt, params))
	if err != nil {
		return nil, fmt.Errorf("keys: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keys: gcm: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, pl, nil)
	tag := verificationTag(passphrase, salt, nonce, ciphertext, params)
	Zeroize(pl)

	return &Envelope{
		Version:         EnvelopeVersion,
		KDF:             KDFNameArgon2ID,
		KDFSalt:         hex.EncodeToString(salt),
		KDFParams:       *params,
		Cipher:          CipherAES256GCM,
		Nonce:           hex.EncodeToString(nonce),
		VerificationTag: hex.EncodeToString(tag),
		KeyType:         KeyTypeED25519,
		Payload:         hex.EncodeToString(ciphertext),
	}, nil
}

// Decrypt opens an envelope JSON payload and returns the private key. The
// passphrase is verified via the dedicated verification key before any
// authenticated decryption, so a wrong passphrase is indistinguishable from a
// corrupt payload. Callers should Zeroize the returned key after use.
func Decrypt(data []byte, passphrase string) (ed25519.PrivateKey, error) {
	env, err := ParseEnvelope(data)
	if err != nil {
		return nil, err
	}
	if env.Version != EnvelopeVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, env.Version)
	}
	if env.KDF != KDFNameArgon2ID || env.Cipher != CipherAES256GCM {
		return nil, fmt.Errorf("%w: kdf=%s cipher=%s", ErrDecryptionFailed, env.KDF, env.Cipher)
	}

	salt, err := hex.DecodeString(env.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("%w: salt", ErrDecryptionFailed)
	}
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce", ErrDecryptionFailed)
	}
	ciphertext, err := hex.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload", ErrDecryptionFailed)
	}
	expectedTag, err := hex.DecodeString(env.VerificationTag)
	if err != nil {
		return nil, fmt.Errorf("%w: tag", ErrDecryptionFailed)
	}

	tag := verificationTag(passphrase, salt, nonce, ciphertext, &env.KDFParams)
	if len(expectedTag) != verificationTagLen || !hmac.Equal(tag, expectedTag) {
		Zeroize(tag)
		return nil, ErrDecryptionFailed
	}
	Zeroize(tag)

	block, err := aes.NewCipher(deriveCipherKey(passphrase, salt, &env.KDFParams))
	if err != nil {
		return nil, fmt.Errorf("%w", ErrDecryptionFailed)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrDecryptionFailed)
	}
	pl, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	var decoded keyPayload
	if err := json.Unmarshal(pl, &decoded); err != nil {
		Zeroize(pl)
		return nil, ErrDecryptionFailed
	}
	Zeroize(pl)

	privRaw, err := base64.StdEncoding.DecodeString(decoded.PrivateKey)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	if len(privRaw) != ed25519.PrivateKeySize {
		Zeroize(privRaw)
		return nil, fmt.Errorf("keys: invalid private key size: got %d, want %d", len(privRaw), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(privRaw) // handed to the caller — they must Zeroize it

	if env.KeyType != "" && env.KeyType != KeyTypeED25519 {
		return nil, fmt.Errorf("keys: unsupported key type %q", env.KeyType)
	}
	return priv, nil
}

// IsEnvelope reports whether data begins with the file-level magic header.
func IsEnvelope(data []byte) bool {
	return bytes.HasPrefix(data, []byte(FileMagic))
}

// ParseEnvelope parses a JSON envelope (magic header not required).
func ParseEnvelope(data []byte) (*Envelope, error) {
	if IsEnvelope(data) {
		data = bytes.TrimPrefix(data, []byte(FileMagic))
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("keys: parse envelope: %w", err)
	}
	return &env, nil
}

// MarshalEnvelope serializes an envelope back to JSON.
func MarshalEnvelope(env *Envelope) ([]byte, error) {
	return json.Marshal(env)
}

// WriteEncryptedFile writes an envelope with the magic header (file mode 0400).
func WriteEncryptedFile(path string, priv ed25519.PrivateKey, passphrase string) error {
	env, err := Encrypt(priv, passphrase, nil)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString(FileMagic)
	buf.Write(env)
	if err := os.WriteFile(path, buf.Bytes(), 0400); err != nil {
		return fmt.Errorf("keys: write encrypted key: %w", err)
	}
	return nil
}

// ReadEncryptedFile reads a magic-header envelope and returns the decrypted
// private key.
func ReadEncryptedFile(path string, passphrase string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- keyring-scoped path validated by callers
	if err != nil {
		return nil, fmt.Errorf("keys: read encrypted key: %w", err)
	}
	if !IsEnvelope(data) {
		return nil, ErrNotEnvelope
	}
	return Decrypt(data, passphrase)
}

// deriveCipherKey runs Argon2id and returns only the 32-byte cipher key.
// The verification key (second half) is never exposed.
func deriveCipherKey(passphrase string, salt []byte, params *KDFParams) []byte {
	return argon2.IDKey([]byte(passphrase), salt, params.T, params.M, params.P, 32)
}

// verificationTag computes HMAC-SHA256(verKey, salt ‖ nonce ‖ ciphertext).
// verKey is the second 32 bytes of the Argon2id output.
func verificationTag(passphrase string, salt, nonce, ciphertext []byte, params *KDFParams) []byte {
	derived := argon2.IDKey([]byte(passphrase), salt, params.T, params.M, params.P, derivedKeyLen)
	verKey := derived[32:64]

	h := hmac.New(sha256.New, verKey)
	h.Write(salt)
	h.Write(nonce)
	h.Write(ciphertext)
	tag := h.Sum(nil)

	Zeroize(derived)
	return tag
}

// Zeroize wipes a byte slice in place. Keys and derived material are wiped
// immediately after use to reduce in-memory exposure.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NormalizePassphrase strips surrounding whitespace from a passphrase read
// from an env var; an all-whitespace passphrase becomes empty.
func NormalizePassphrase(p string) string {
	return strings.TrimSpace(p)
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// InitStore creates a new wardex-trust.yaml with the bootstrap admin key.
// Fails if the output file already exists.
func InitStore(keyPath, actor, name, outPath string) error {
	// Fail if trust store already exists
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("trust init: %q already exists — cannot re-initialise.\n"+
			"If you need to start over, remove the file first (this is destructive)", outPath)
	}

	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("trust init: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	keyID := generateKeyID(name, string(RoleAdmin), nil)

	entry := KeyEntry{
		ID:      keyID,
		PubKey:  EncodePublicKey(pub),
		Role:    RoleAdmin,
		Actor:   actor,
		Name:    name,
		AddedAt: time.Now().UTC().Truncate(time.Second),
		AddedBy: "bootstrap",
	}

	// Sign the entry
	entryMsg := canonicalKeyEntryMessage(&entry)
	entry.AddedSig = Sign(priv, entryMsg)

	store := &TrustStore{
		Version:   "1",
		CreatedAt: time.Now().UTC(),
		CreatedBy: actor,
		Keys:      []KeyEntry{entry},
	}

	// Compute root signature
	store.RootSig = computeRootSig(store, priv)

	return saveStore(outPath, store)
}

// AddKey adds a new actor to the trust store.
// Requires the signing key to have role admin.
func AddKey(storePath, keyPath, pubkeyPath string, role Role, actor, name string) error {
	if !role.IsValid() {
		return fmt.Errorf("trust add: invalid role %q", role)
	}

	store, _, err := LoadStore(storePath)
	if err != nil {
		return fmt.Errorf("trust add: %w", err)
	}

	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("trust add: %w", err)
	}

	// Verify signer is an active admin
	signerEntry, err := findKeyByPublicKey(store, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return fmt.Errorf("trust add: signer key not found in trust store: %w", err)
	}
	if signerEntry.Role != RoleAdmin {
		return fmt.Errorf("trust add: key %s (%s) has role %q — adding keys requires role %q",
			signerEntry.ID, signerEntry.Actor, signerEntry.Role, RoleAdmin)
	}

	// Check duplicate actor
	for _, k := range store.Keys {
		if k.Actor == actor && !isRevoked(store, k.ID) {
			return fmt.Errorf("trust add: %s already has an active entry (%s).\n"+
				"       Use wardex trust revoke to revoke the existing key first", actor, k.ID)
		}
	}

	// Load new public key
	newPub, err := LoadPublicKeyFile(pubkeyPath)
	if err != nil {
		return fmt.Errorf("trust add: %w", err)
	}

	keyID := generateKeyID(name, string(role), store.Keys)

	entry := KeyEntry{
		ID:      keyID,
		PubKey:  EncodePublicKey(newPub),
		Role:    role,
		Actor:   actor,
		Name:    name,
		AddedAt: time.Now().UTC().Truncate(time.Second),
		AddedBy: signerEntry.Actor,
	}

	entryMsg := canonicalKeyEntryMessage(&entry)
	entry.AddedSig = Sign(priv, entryMsg)

	store.Keys = append(store.Keys, entry)
	store.RootSig = computeRootSig(store, priv)

	return saveStore(storePath, store)
}

// RevokeKey adds a revocation entry to the trust store.
// Requires the signing key to have role admin.
func RevokeKey(storePath, keyPath, keyID, reason string) error {
	if len(reason) < 10 {
		return fmt.Errorf("trust revoke: reason must be at least 10 characters")
	}

	store, _, err := LoadStore(storePath)
	if err != nil {
		return fmt.Errorf("trust revoke: %w", err)
	}

	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("trust revoke: %w", err)
	}

	// Verify signer is an active admin
	signerEntry, err := findKeyByPublicKey(store, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return fmt.Errorf("trust revoke: signer key not found in trust store: %w", err)
	}
	if signerEntry.Role != RoleAdmin {
		return fmt.Errorf("trust revoke: key %s (%s) has role %q — revoking keys requires role %q",
			signerEntry.ID, signerEntry.Actor, signerEntry.Role, RoleAdmin)
	}

	// Verify the target key exists
	found := false
	for _, k := range store.Keys {
		if k.ID == keyID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("trust revoke: key %q not found in trust store", keyID)
	}

	// Check if already revoked
	if isRevoked(store, keyID) {
		return fmt.Errorf("trust revoke: key %q is already revoked", keyID)
	}

	revocation := Revocation{
		KeyID:     keyID,
		RevokedAt: time.Now().UTC().Truncate(time.Second),
		RevokedBy: signerEntry.Actor,
		Reason:    reason,
	}

	revMsg := canonicalRevocationMessage(&revocation)
	revocation.Sig = Sign(priv, revMsg)

	store.Revocations = append(store.Revocations, revocation)
	store.RootSig = computeRootSig(store, priv)

	return saveStore(storePath, store)
}

// LoadStore reads and parses a wardex-trust.yaml file.
// Returns the parsed store and the raw bytes (needed for TrustStoreSig verification).
func LoadStore(path string) (*TrustStore, []byte, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, nil, fmt.Errorf("trust store: read %q: %w", path, err)
	}
	var store TrustStore
	if err := yaml.Unmarshal(data, &store); err != nil {
		return nil, nil, fmt.Errorf("trust store: parse %q: %w", path, err)
	}
	if store.Version == "" {
		return nil, nil, fmt.Errorf("trust store: %q is missing version field", path)
	}
	return &store, data, nil
}

// LoadStoreFromBytes parses a trust store from raw bytes (used for remote fetch).
func LoadStoreFromBytes(data []byte) (*TrustStore, error) {
	var store TrustStore
	if err := yaml.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("trust store: parse: %w", err)
	}
	if store.Version == "" {
		return nil, fmt.Errorf("trust store: missing version field")
	}
	return &store, nil
}

// VerifyRootSig verifies the root signature of a trust store.
// It finds the admin key that created the signature and validates it.
func VerifyRootSig(store *TrustStore) error {
	rootMsg := rootSigMessage(store)

	// Try each admin key to find the one that signed
	for _, k := range store.Keys {
		if k.Role != RoleAdmin {
			continue
		}
		pub, err := DecodePublicKey(k.PubKey)
		if err != nil {
			continue
		}
		if err := Verify(pub, rootMsg, store.RootSig); err == nil {
			return nil // Valid signature found
		}
	}

	return fmt.Errorf("trust store: root signature invalid — file may have been tampered with")
}

// ActiveKey returns a key entry if it exists and is not revoked.
func ActiveKey(store *TrustStore, keyID string) (*KeyEntry, error) {
	for i, k := range store.Keys {
		if k.ID == keyID {
			if isRevoked(store, keyID) {
				return nil, fmt.Errorf("key %q (%s) has been revoked", keyID, k.Actor)
			}
			return &store.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("key %q not found in trust store", keyID)
}

// SHA256Sum computes the SHA-256 hex digest of data.
func SHA256Sum(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// --- Internal helpers ---

func isRevoked(store *TrustStore, keyID string) bool {
	for _, r := range store.Revocations {
		if r.KeyID == keyID {
			return true
		}
	}
	return false
}

func findKeyByPublicKey(store *TrustStore, pub ed25519.PublicKey) (*KeyEntry, error) {
	encoded := EncodePublicKey(pub)
	for i, k := range store.Keys {
		if k.PubKey == encoded {
			if isRevoked(store, k.ID) {
				return nil, fmt.Errorf("key %s (%s) has been revoked", k.ID, k.Actor)
			}
			return &store.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("public key not found in trust store")
}

func canonicalKeyEntryMessage(entry *KeyEntry) []byte {
	msg := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s",
		entry.ID,
		entry.PubKey,
		entry.Role,
		entry.Actor,
		entry.Name,
		entry.AddedAt.UTC().Format(time.RFC3339),
		entry.AddedBy,
	)
	return []byte(msg)
}

func canonicalRevocationMessage(rev *Revocation) []byte {
	msg := fmt.Sprintf("%s\n%s\n%s\n%s",
		rev.KeyID,
		rev.RevokedAt.UTC().Format(time.RFC3339),
		rev.RevokedBy,
		rev.Reason,
	)
	return []byte(msg)
}

// rootSigMessage computes the canonical message for the root signature.
// It is the SHA-256 of all AddedSig and Revocation.Sig concatenated in order.
func rootSigMessage(store *TrustStore) []byte {
	h := sha256.New()
	for _, k := range store.Keys {
		h.Write([]byte(k.AddedSig))
	}
	for _, r := range store.Revocations {
		h.Write([]byte(r.Sig))
	}
	return h.Sum(nil)
}

func computeRootSig(store *TrustStore, adminKey ed25519.PrivateKey) string {
	msg := rootSigMessage(store)
	return Sign(adminKey, msg)
}

func saveStore(path string, store *TrustStore) error {
	data, err := yaml.Marshal(store)
	if err != nil {
		return fmt.Errorf("trust store: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("trust store: write %q: %w", path, err)
	}
	return nil
}

// generateKeyID produces an ID in the format <initials>-<role>-<seq>.
// E.g., "Carlos Mendes" with role admin → "cm-admin-01".
func generateKeyID(fullName string, role string, existing []KeyEntry) string {
	initials := extractInitials(fullName)
	prefix := fmt.Sprintf("%s-%s-", initials, role)

	maxSeq := 0
	for _, k := range existing {
		if strings.HasPrefix(k.ID, prefix) {
			// Parse the sequence number
			suffix := strings.TrimPrefix(k.ID, prefix)
			var seq int
			if _, err := fmt.Sscanf(suffix, "%d", &seq); err == nil {
				if seq > maxSeq {
					maxSeq = seq
				}
			}
		}
	}

	return fmt.Sprintf("%s%02d", prefix, maxSeq+1)
}

func extractInitials(fullName string) string {
	parts := strings.Fields(fullName)
	var initials []rune
	for _, part := range parts {
		for _, r := range part {
			initials = append(initials, unicode.ToLower(r))
			break
		}
	}
	if len(initials) == 0 {
		return "xx"
	}
	return string(initials)
}

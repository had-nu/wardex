// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"
)

// SealConfig reads a draft wardex-config.yaml, verifies there are no
// PENDING_APPROVAL fields, and produces a signed wardex.wexstate file.
// Only ciso or admin roles can seal.
func SealConfig(keyPath, inputPath, outPath, trustRef string) error {
	// 1. Resolve and load trust store
	ref := ResolveTrustStoreRef(trustRef, "")
	storeData, err := FetchTrustStore(ref)
	if err != nil {
		return fmt.Errorf("config seal: %w", err)
	}
	store, err := LoadStoreFromBytes(storeData)
	if err != nil {
		return fmt.Errorf("config seal: %w", err)
	}
	if err := VerifyRootSig(store); err != nil {
		return fmt.Errorf("config seal: %w", err)
	}

	// 2. Load and validate signer key
	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("config seal: %w", err)
	}

	signerEntry, err := findKeyByPublicKey(store, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return fmt.Errorf("config seal: %w", err)
	}

	if !CanPerform(signerEntry.Role, OpConfigSeal) {
		return fmt.Errorf("config seal: key %s (%s) has role %q.\n"+
			"       Sealing requires role %q or %q",
			signerEntry.ID, signerEntry.Actor, signerEntry.Role, RoleCISO, RoleAdmin)
	}

	// 3. Read and validate the draft config
	draftData, err := os.ReadFile(inputPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("config seal: read draft %q: %w", inputPath, err)
	}

	pendingFields, err := DetectPendingApproval(draftData)
	if err != nil {
		return fmt.Errorf("config seal: %w", err)
	}
	if len(pendingFields) > 0 {
		msg := "config seal: draft contains unsettled fields:\n"
		for _, f := range pendingFields {
			msg += fmt.Sprintf("  - %s: \"PENDING_APPROVAL\"\n", f)
		}
		msg += "\nThese fields require a decision from the risk owner before sealing."
		return fmt.Errorf("%s", msg)
	}

	// 4. Build WexState
	state := &WexState{
		Version:       "1",
		SealedAt:      time.Now().UTC().Truncate(time.Second),
		SealedBy:      signerEntry.Actor,
		SealedByKeyID: signerEntry.ID,
		TrustStoreRef: ref,
		TrustStoreSig: SHA256Sum(storeData),
		Payload:       string(draftData),
	}

	// 5. Sign
	msg := SealMessage(state)
	state.Sig = Sign(priv, msg)

	// 6. Write .wexstate
	return SaveWexState(outPath, state)
}

// VerifySeal verifies the integrity of a sealed config against the trust store.
// Called at the beginning of evaluate, before any access to the payload.
func VerifySeal(state *WexState, store *TrustStore, storeRawBytes []byte) error {
	// 1. Verify the signer key exists and is not revoked
	key, err := ActiveKey(store, state.SealedByKeyID)
	if err != nil {
		return fmt.Errorf("seal verification: key %q: %w", state.SealedByKeyID, err)
	}

	// 2. Verify the trust store has not changed since the seal
	currentSig := SHA256Sum(storeRawBytes)
	if currentSig != state.TrustStoreSig {
		return fmt.Errorf(
			"seal verification: trust store has changed since seal.\n"+
				"The config must be re-sealed by %s.\n"+
				"Run: wardex config seal --keyring <ciso-keyring> --input wardex-config.yaml",
			key.Actor,
		)
	}

	// 3. Verify the ed25519 signature over the payload
	pub, err := DecodePublicKey(key.PubKey)
	if err != nil {
		return fmt.Errorf("seal verification: decode pubkey: %w", err)
	}

	msg := SealMessage(state)
	if err := Verify(pub, msg, state.Sig); err != nil {
		return fmt.Errorf("seal verification: signature invalid — file may have been tampered with")
	}

	return nil
}

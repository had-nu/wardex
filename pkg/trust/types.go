// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package trust implements the Wardex Trust Store & Sealed Config (wexstate)
// system as specified in SPEC_wardex_trust_.md v1.0.0.
//
// It provides:
//   - Ed25519 keypair generation and keyring management
//   - Trust store (wardex-trust.yaml) lifecycle: init, add, revoke
//   - Config sealing (wardex.wexstate) and verification
//   - Role-based access control for trust operations
package trust

import (
	"time"
)

// Role defines operator permissions. Compared as constants, never as free strings.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleCISO    Role = "ciso"
	RoleAnalyst Role = "analyst"
)

// ValidRoles returns all valid roles for input validation.
func ValidRoles() []Role {
	return []Role{RoleAdmin, RoleCISO, RoleAnalyst}
}

// IsValid checks whether the role is a recognised Wardex role.
func (r Role) IsValid() bool {
	for _, valid := range ValidRoles() {
		if r == valid {
			return true
		}
	}
	return false
}

// Operation represents a discrete action that can be gated by role.
type Operation string

const (
	OpTrustInit     Operation = "trust.init"
	OpTrustAdd      Operation = "trust.add"
	OpTrustRevoke   Operation = "trust.revoke"
	OpConfigSeal    Operation = "config.seal"
	OpEvaluate      Operation = "evaluate"
	OpReport        Operation = "report"
	OpAcceptRequest Operation = "accept.request"
	OpAcceptApprove Operation = "accept.approve"
)

// RolePermissions defines what each role can execute.
var RolePermissions = map[Role][]Operation{
	RoleAdmin: {
		OpTrustInit, OpTrustAdd, OpTrustRevoke,
		OpConfigSeal, OpEvaluate, OpReport, OpAcceptRequest,
	},
	RoleCISO: {
		OpConfigSeal, OpEvaluate, OpReport, OpAcceptRequest, OpAcceptApprove,
	},
	RoleAnalyst: {
		OpEvaluate, OpReport, OpAcceptRequest,
	},
}

// CanPerform checks whether a role is authorised for the given operation.
func CanPerform(role Role, op Operation) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == op {
			return true
		}
	}
	return false
}

// KeyEntry represents a key in the trust store.
// Each entry is immutable after creation — revocation adds a Revocation entry,
// it does not modify KeyEntry directly.
type KeyEntry struct {
	ID       string    `yaml:"id"`        // format: <initials>-<role>-<seq>, e.g. "km-admin-01"
	PubKey   string    `yaml:"pubkey"`    // "ed25519:<base64>"
	Role     Role      `yaml:"role"`      // admin | ciso | analyst
	Actor    string    `yaml:"actor"`     // email
	Name     string    `yaml:"name"`      // full name for audit log
	AddedAt  time.Time `yaml:"added_at"`
	AddedBy  string    `yaml:"added_by"`  // actor email or "bootstrap"
	AddedSig string    `yaml:"added_sig"` // ed25519 signature of the entry by AddedBy
}

// Revocation is append-only. It never modifies KeyEntry.
// The trust store loader marks the KeyEntry as revoked when it finds
// a Revocation with a matching KeyID.
type Revocation struct {
	KeyID     string    `yaml:"key_id"`
	RevokedAt time.Time `yaml:"revoked_at"`
	RevokedBy string    `yaml:"revoked_by"` // actor email
	Reason    string    `yaml:"reason"`
	Sig       string    `yaml:"sig"` // ed25519 signature of this revocation by RevokedBy
}

// TrustStore is the wardex-trust.yaml file.
// The file has a covering signature (RootSig) calculated over the SHA-256
// hash of all KeyEntry.AddedSig and Revocation.Sig, in insertion order.
// Any manual modification invalidates RootSig.
type TrustStore struct {
	Version     string       `yaml:"version"`
	CreatedAt   time.Time    `yaml:"created_at"`
	CreatedBy   string       `yaml:"created_by"` // actor email
	Keys        []KeyEntry   `yaml:"keys"`
	Revocations []Revocation `yaml:"revocations"`
	RootSig     string       `yaml:"root_sig"` // admin signature over the store state
}

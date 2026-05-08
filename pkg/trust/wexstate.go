// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// WexState is the wardex.wexstate file.
// Payload is the content of wardex-config.yaml serialised as a YAML string.
// The Sig covers: Version + Payload + SealedAt + SealedBy + TrustStoreRef + TrustStoreSig.
// The evaluate command verifies Sig before deserialising Payload.
type WexState struct {
	Version       string    `yaml:"version"`
	SealedAt      time.Time `yaml:"sealed_at"`
	SealedBy      string    `yaml:"sealed_by"`        // actor email
	SealedByKeyID string    `yaml:"sealed_by_key_id"` // KeyEntry.ID of the signer
	TrustStoreRef string    `yaml:"trust_store_ref"`   // URL or relative path to wardex-trust.yaml
	TrustStoreSig string    `yaml:"trust_store_sig"`   // SHA-256 of wardex-trust.yaml at seal time
	Payload       string    `yaml:"payload"`           // wardex-config.yaml content
	Sig           string    `yaml:"sig"`               // ed25519 signature
}

// LoadWexState reads and parses a .wexstate file.
func LoadWexState(path string) (*WexState, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("wexstate: read %q: %w", path, err)
	}
	var state WexState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("wexstate: parse %q: %w", path, err)
	}
	if state.Version == "" {
		return nil, fmt.Errorf("wexstate: %q is missing version field", path)
	}
	return &state, nil
}

// SaveWexState writes a WexState to disk.
func SaveWexState(path string, state *WexState) error {
	data, err := yaml.Marshal(state)
	if err != nil {
		return fmt.Errorf("wexstate: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("wexstate: write %q: %w", path, err)
	}
	return nil
}

// SealMessage computes the canonical message for signing a WexState.
// The message is: Version + Payload + SealedAt(RFC3339) + SealedBy + TrustStoreRef + TrustStoreSig.
func SealMessage(state *WexState) []byte {
	msg := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		state.Version,
		state.Payload,
		state.SealedAt.UTC().Format(time.RFC3339),
		state.SealedBy,
		state.TrustStoreRef,
		state.TrustStoreSig,
	)
	return []byte(msg)
}

// pendingApprovalSentinel is the magic string that blocks config sealing.
const pendingApprovalSentinel = "PENDING_APPROVAL"

// DetectPendingApproval scans YAML content for any value equal to "PENDING_APPROVAL".
// Returns a list of dotted field paths where PENDING_APPROVAL was found.
func DetectPendingApproval(yamlContent []byte) ([]string, error) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(yamlContent, &raw); err != nil {
		return nil, fmt.Errorf("detect pending: parse yaml: %w", err)
	}
	var pending []string
	walkYAML("", raw, &pending)
	return pending, nil
}

// walkYAML recursively walks a YAML tree looking for PENDING_APPROVAL values.
func walkYAML(prefix string, node interface{}, pending *[]string) {
	switch v := node.(type) {
	case map[string]interface{}:
		for key, val := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			walkYAML(path, val, pending)
		}
	case string:
		if strings.TrimSpace(v) == pendingApprovalSentinel {
			*pending = append(*pending, prefix)
		}
	case []interface{}:
		for i, item := range v {
			path := fmt.Sprintf("%s[%d]", prefix, i)
			walkYAML(path, item, pending)
		}
	}
}

// IsWexStatePath checks if a path refers to a .wexstate file (by extension).
func IsWexStatePath(path string) bool {
	return strings.HasSuffix(path, ".wexstate")
}

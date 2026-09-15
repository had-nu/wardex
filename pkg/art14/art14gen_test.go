// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package art14

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

var testSecret = []byte("test-secret-key-123456789012345678901234")

func TestCurrentArtifactVersionIsSupported(t *testing.T) {
	a, err := GenerateArtefact([]string{"CVE-2024-3094"}, time.Now().UTC(), Config{GeneratedBy: "wardex/v2.6.0"})
	if err != nil {
		t.Fatalf("GenerateArtefact: %v", err)
	}

	if a.FormatVersion != model.Art14FormatVersion {
		t.Errorf("format_version = %d, want %d", a.FormatVersion, model.Art14FormatVersion)
	}
	if want := model.CapabilityHMACSHA256 | model.CapabilityCanonicalJSON; a.Capabilities != want {
		t.Errorf("capabilities = %b, want %b", a.Capabilities, want)
	}

	if err := CheckVersionSupported(a); err != nil {
		t.Fatalf("CheckVersionSupported(current) = %v", err)
	}

	if err := SignArtefact(a, testSecret); err != nil {
		t.Fatalf("SignArtefact: %v", err)
	}
	if err := VerifyArtefact(a, testSecret); err != nil {
		t.Fatalf("VerifyArtefact(current) = %v", err)
	}
}

func TestLegacyArtifactWithoutVersionStillVerifies(t *testing.T) {
	cur, err := GenerateArtefact([]string{"CVE-2024-3094"}, time.Now().UTC(), Config{GeneratedBy: "wardex/v2.6.0"})
	if err != nil {
		t.Fatalf("GenerateArtefact: %v", err)
	}

	// Build a genuine pre-2.6 artefact: strip format_version and capabilities,
	// then sign the version-less canonical JSON exactly like 2.5.0 did.
	data, err := json.Marshal(cur)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	delete(raw, "format_version")
	delete(raw, "capabilities")
	legacy, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}

	var legacyArt model.Art14NotificationArtefact
	if err := json.Unmarshal(legacy, &legacyArt); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if err := SignArtefact(&legacyArt, testSecret); err != nil {
		t.Fatalf("SignArtefact(legacy): %v", err)
	}
	signed, err := json.Marshal(legacyArt)
	if err != nil {
		t.Fatalf("re-marshal signed legacy: %v", err)
	}

	path := filepath.Join(t.TempDir(), "wardex-art14-legacy.json")
	if err := os.WriteFile(path, signed, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	read, err := ReadArtefact(path)
	if err != nil {
		t.Fatalf("read legacy artefact must be tolerant: %v", err)
	}
	if read.FormatVersion != 0 {
		t.Errorf("legacy format_version = %d, want 0", read.FormatVersion)
	}
	if read.Capabilities != 0 {
		t.Errorf("legacy capabilities = %d, want 0", read.Capabilities)
	}

	// Pre-2.6 artefacts carry the same HMAC-SHA256 scheme, so verification
	// must keep accepting them (rule P2 — no silent clamp anywhere).
	if err := VerifyArtefact(read, testSecret); err != nil {
		t.Fatalf("VerifyArtefact(legacy) = %v", err)
	}
}

func TestFutureFormatVersionRejectedAtVerify(t *testing.T) {
	a, err := GenerateArtefact([]string{"CVE-2024-3094"}, time.Now().UTC(), Config{GeneratedBy: "wardex/v2.6.0"})
	if err != nil {
		t.Fatalf("GenerateArtefact: %v", err)
	}
	if err := SignArtefact(a, testSecret); err != nil {
		t.Fatalf("SignArtefact: %v", err)
	}

	// A future build bumping the format version must be rejected with the
	// controlled error, never silently downgraded to version 1.
	a.FormatVersion = model.Art14FormatVersion + 1
	if err := VerifyArtefact(a, testSecret); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("VerifyArtefact(future) = %v, want ErrUnsupportedFormat", err)
	}
}

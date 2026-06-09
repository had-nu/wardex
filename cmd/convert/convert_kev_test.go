// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package convert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/wardex/pkg/model"
)

func TestKEVCorrelation(t *testing.T) {
	// 1. Prepare mock catalogue
	catalogue := &KEVCatalogue{
		Title:          "Mock KEV Catalog",
		CatalogVersion: "1.0",
		DateReleased:   "2026-06-09T00:00:00Z",
		Count:          1,
		Vulnerabilities: []KEVEntry{
			{
				CveID:             "CVE-2024-3094",
				VendorProject:     "XZ Utils",
				Product:           "xz",
				VulnerabilityName: "Backdoor in upstream release",
				DateAdded:         "2024-03-29",
				ShortDescription:  "Backdoor introduced in build system.",
			},
		},
	}

	// Test CorrelateKEV
	vulns := []model.Vulnerability{
		{
			CVEID: "CVE-2024-3094",
		},
		{
			CVEID: "CVE-2023-1234",
		},
	}

	correlated := CorrelateKEV(vulns, catalogue)
	if len(correlated) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(correlated))
	}

	// Check CVE-2024-3094 (in KEV)
	v1 := correlated[0]
	if !v1.ActivelyExploited {
		t.Errorf("expected CVE-2024-3094 to be actively exploited")
	}
	if v1.ExploitedSource != "cisa-kev" {
		t.Errorf("expected exploited source to be cisa-kev, got %q", v1.ExploitedSource)
	}
	expectedTime, _ := time.Parse("2006-01-02", "2024-03-29")
	if !v1.ActivelyExploitedSince.Equal(expectedTime.UTC()) {
		t.Errorf("expected actively exploited since %v, got %v", expectedTime.UTC(), v1.ActivelyExploitedSince)
	}

	// Check CVE-2023-1234 (not in KEV)
	v2 := correlated[1]
	if v2.ActivelyExploited {
		t.Errorf("expected CVE-2023-1234 not to be actively exploited")
	}
	if v2.ExploitedSource != "" {
		t.Errorf("expected empty exploited source, got %q", v2.ExploitedSource)
	}
	if !v2.ActivelyExploitedSince.IsZero() {
		t.Errorf("expected zero time for actively exploited since, got %v", v2.ActivelyExploitedSince)
	}
}

func TestLoadKEVCatalogue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kev.json")

	mockCatalog := KEVCatalogue{
		Title: "Test",
		Vulnerabilities: []KEVEntry{
			{CveID: "CVE-2024-1234"},
		},
	}
	data, err := json.Marshal(mockCatalog)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	cat, err := LoadKEVCatalogue(path)
	if err != nil {
		t.Fatalf("unexpected error loading KEV: %v", err)
	}

	if cat.Title != "Test" || len(cat.Vulnerabilities) != 1 || cat.Vulnerabilities[0].CveID != "CVE-2024-1234" {
		t.Errorf("loaded catalogue did not match expected structure: %+v", cat)
	}
}

func TestCheckKEVAge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kev.json")

	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Fresh file (age is small) -> should not warn
	warn := CheckKEVAge(path, 7)
	if warn != "" {
		t.Errorf("expected empty warning for fresh file, got: %q", warn)
	}

	// 2. Stale file (old mod time) -> should warn
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	warn = CheckKEVAge(path, 7)
	if warn == "" {
		t.Errorf("expected warning for stale file (10 days old, threshold 7)")
	}

	// 3. Threshold <= 0 -> disabled, should not warn
	warn = CheckKEVAge(path, 0)
	if warn != "" {
		t.Errorf("expected empty warning when age check is disabled (threshold 0), got: %q", warn)
	}
}

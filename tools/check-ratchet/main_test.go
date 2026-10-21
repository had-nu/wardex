// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseProfileAggregatesBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coverage.out")
	content := `mode: set
github.com/had-nu/wardex/v2/pkg/alpha/a.go:1.1,2.2 4 1
github.com/had-nu/wardex/v2/pkg/alpha/b.go:1.1,2.2 6 0
github.com/had-nu/wardex/v2/pkg/beta/c.go:1.1,2.2 3 2
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	counts, err := parseProfile(path)
	if err != nil {
		t.Fatalf("parseProfile: %v", err)
	}
	if got := counts["github.com/had-nu/wardex/v2/pkg/alpha"]; got != [2]int{10, 4} {
		t.Errorf("alpha = %v, want {10 4}", got)
	}
	if got := counts["github.com/had-nu/wardex/v2/pkg/beta"]; got != [2]int{3, 3} {
		t.Errorf("beta = %v, want {3 3}", got)
	}
}

func TestCheckCoverage(t *testing.T) {
	baseline := coverageBaseline{
		Version:     baselineVersion,
		GlobalFloor: 40,
		Packages: map[string]coverageFloor{
			"pkg/alpha": {Floor: 50},
			"pkg/beta":  {Floor: 0, Untested: true},
		},
	}
	current := map[string]coverageRow{
		"pkg/alpha": {Statements: 10, Covered: 5, Percent: 50},
		"pkg/beta":  {Statements: 0},
	}
	var out, errOut bytes.Buffer
	if code := checkCoverage(baseline, current, &out, &errOut); code != 0 {
		t.Fatalf("clean check exit = %d, stderr=%s", code, errOut.String())
	}

	current["pkg/alpha"] = coverageRow{Statements: 10, Covered: 4, Percent: 40}
	out.Reset()
	errOut.Reset()
	if code := checkCoverage(baseline, current, &out, &errOut); code != 1 {
		t.Fatalf("regression exit = %d, want 1", code)
	}
}

func TestCheckCoverageDetectsStaleBaseline(t *testing.T) {
	baseline := coverageBaseline{Version: baselineVersion, GlobalFloor: 0, Packages: map[string]coverageFloor{
		"pkg/gone": {Floor: 50},
	}}
	current := map[string]coverageRow{"pkg/alpha": {Statements: 1, Covered: 1, Percent: 100}}
	var out, errOut bytes.Buffer
	if code := checkCoverage(baseline, current, &out, &errOut); code != 2 {
		t.Fatalf("stale exit = %d, want 2", code)
	}
}

func TestUpdateCoverageRaisesFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coverage.json")
	old := coverageBaseline{Version: baselineVersion, GlobalFloor: 40, Packages: map[string]coverageFloor{
		"pkg/alpha": {Floor: 50},
	}}
	current := map[string]coverageRow{
		"pkg/alpha": {Statements: 10, Covered: 6, Percent: 60},
		"pkg/beta":  {Statements: 0},
	}
	var out, errOut bytes.Buffer
	if code := updateCoverage(path, old, current, &out, &errOut); code != 0 {
		t.Fatalf("update exit = %d, stderr=%s", code, errOut.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got coverageBaseline
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Packages["pkg/alpha"].Floor != 60 {
		t.Errorf("alpha floor = %v, want 60", got.Packages["pkg/alpha"].Floor)
	}
	if !got.Packages["pkg/beta"].Untested {
		t.Errorf("beta = %+v, want untested", got.Packages["pkg/beta"])
	}
}

func TestUpdateCoverageRefusesDecrease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coverage.json")
	old := coverageBaseline{Version: baselineVersion, GlobalFloor: 40, Packages: map[string]coverageFloor{
		"pkg/alpha": {Floor: 50},
	}}
	current := map[string]coverageRow{
		"pkg/alpha": {Statements: 10, Covered: 4, Percent: 40},
	}
	var out, errOut bytes.Buffer
	if code := updateCoverage(path, old, current, &out, &errOut); code != 1 {
		t.Fatalf("update exit = %d, want 1 (stderr=%s)", code, errOut.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("baseline was written despite a refused decrease")
	}
}

func TestScanNosec(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go": "package a\n// #nosec G304 — path validated by the caller\n",
		"b.go": "package b\n// #nosec G304\n",
		"c.go": "package c\n// #nosec\n",
		"d.go": "package d\n// #nosec G101 G102 -- fixture key is public test data\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := scanNosec(dir)
	if err != nil {
		t.Fatalf("scanNosec: %v", err)
	}
	want := map[string]int{"b.go|G304": 1, "c.go|none": 1}
	if len(counts) != len(want) {
		t.Fatalf("counts = %v, want %v", counts, want)
	}
	for key, n := range want {
		if counts[key] != n {
			t.Errorf("%s = %d, want %d", key, counts[key], n)
		}
	}
}

func TestNosecUpdateRefusesIncrease(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n// #nosec G304\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "nosec.json")
	if err := writeJSON(baselinePath, nosecBaseline{Version: baselineVersion, Occurrences: map[string]int{}}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runNosec(baselinePath, dir, true, &out, &errOut); code != 1 {
		t.Fatalf("update exit = %d, want 1 (stderr=%s)", code, errOut.String())
	}
}

func TestNosecUpdateCreatesInitialBaseline(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n// #nosec G304\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "nosec.json")
	var out, errOut bytes.Buffer
	if code := runNosec(baselinePath, dir, true, &out, &errOut); code != 0 {
		t.Fatalf("initial update exit = %d, stderr=%s", code, errOut.String())
	}
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	var got nosecBaseline
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Occurrences["a.go|G304"] != 1 {
		t.Fatalf("occurrences = %v, want a.go|G304 = 1", got.Occurrences)
	}
}

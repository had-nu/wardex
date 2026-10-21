// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// testManifest is a small graph with one package per module. Tests add
// packages or dependencies only when the rule under test needs them.
func testManifest() *manifest {
	return &manifest{
		Version: 1,
		Modules: map[string]moduleSpec{
			"contracts":  {Packages: []string{"pkg/contracts"}},
			"kit":        {Packages: []string{"pkg/kit"}, MayImport: []string{"contracts"}},
			"assess":     {Packages: []string{"pkg/assess"}, MayImport: []string{"contracts", "kit"}},
			"regulatory": {Packages: []string{"pkg/regulatory"}, MayImport: []string{"contracts", "kit"}},
			"gate":       {Packages: []string{"pkg/gate"}, MayImport: []string{"contracts", "kit"}},
			"facade":     {Packages: []string{"pkg/sdk"}, MayImport: []string{"assess", "regulatory", "gate", "contracts", "kit"}},
			"adapters":   {Packages: []string{"cmd", "pkg/ui"}, MayImport: []string{"facade", "contracts", "kit"}},
			"tests":      {Packages: []string{"test"}, MayImport: []string{"facade", "contracts", "kit"}},
			"tools":      {Packages: []string{"tools"}},
		},
	}
}

// makeGraph builds a graph from edges and guarantees that every imported
// package also exists as a node.
func makeGraph(edges map[string][]string) graph {
	g := make(graph)
	ensure := func(pkg string) {
		if g[pkg] == nil {
			g[pkg] = &pkgInfo{Path: pkg, Imports: make(map[string]string)}
		}
	}
	for from, targets := range edges {
		ensure(from)
		for _, to := range targets {
			ensure(to)
			g[from].Imports[to] = "input.go:1"
		}
	}
	return g
}

func analyse(t *testing.T, m *manifest, g graph) (*engine, []finding, []string) {
	t.Helper()
	e, err := newEngine(m, g)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	if len(e.unclassified) > 0 {
		t.Fatalf("unexpected unclassified packages: %v", e.unclassified)
	}
	e.computeFindings()
	findings, stale := e.compareBaseline()
	return e, findings, stale
}

func ruleFor(t *testing.T, findings []finding, from, to string) string {
	t.Helper()
	for _, f := range findings {
		if f.From == from && f.To == to {
			return f.Rule
		}
	}
	return ""
}

func TestRuleR1ContractsAndKit(t *testing.T) {
	g := makeGraph(map[string][]string{
		"pkg/contracts": {"pkg/kit"},
		"pkg/kit":       {"pkg/assess"},
		"pkg/assess":    {},
	})
	_, findings, _ := analyse(t, testManifest(), g)
	if got := ruleFor(t, findings, "pkg/contracts", "pkg/kit"); got != "R1" {
		t.Errorf("contracts -> kit: got %q, want R1", got)
	}
	if got := ruleFor(t, findings, "pkg/kit", "pkg/assess"); got != "R1" {
		t.Errorf("kit -> assess: got %q, want R1", got)
	}
}

func TestRuleR2ModuleImportsOnlyAllowedModules(t *testing.T) {
	g := makeGraph(map[string][]string{
		"pkg/assess": {"pkg/gate"},
		"pkg/gate":   {},
	})
	_, findings, _ := analyse(t, testManifest(), g)
	if got := ruleFor(t, findings, "pkg/assess", "pkg/gate"); got != "R2" {
		t.Errorf("assess -> gate: got %q, want R2", got)
	}
}

func TestRuleR3OnlyFacadeAggregatesModules(t *testing.T) {
	m := testManifest()
	assess := m.Modules["assess"]
	assess.MayImport = []string{"contracts", "kit", "gate", "regulatory"}
	m.Modules["assess"] = assess

	g := makeGraph(map[string][]string{
		"pkg/assess":     {"pkg/gate", "pkg/regulatory"},
		"pkg/gate":       {},
		"pkg/regulatory": {},
	})
	_, findings, _ := analyse(t, m, g)
	if got := ruleFor(t, findings, "pkg/assess", "pkg/gate"); got != "R3" {
		t.Errorf("assess -> gate: got %q, want R3", got)
	}
	if got := ruleFor(t, findings, "pkg/assess", "pkg/regulatory"); got != "R3" {
		t.Errorf("assess -> regulatory: got %q, want R3", got)
	}
}

func TestFacadeMayAggregateModules(t *testing.T) {
	g := makeGraph(map[string][]string{
		"pkg/sdk":    {"pkg/assess", "pkg/gate"},
		"pkg/assess": {},
		"pkg/gate":   {},
	})
	_, findings, _ := analyse(t, testManifest(), g)
	if len(findings) != 0 {
		t.Errorf("facade aggregation flagged: %+v", findings)
	}
}

func TestRuleR4OnlyAdaptersImportUI(t *testing.T) {
	g := makeGraph(map[string][]string{
		"pkg/gate": {"pkg/ui"},
		"pkg/ui":   {},
	})
	_, findings, _ := analyse(t, testManifest(), g)
	if got := ruleFor(t, findings, "pkg/gate", "pkg/ui"); got != "R4" {
		t.Errorf("gate -> ui: got %q, want R4", got)
	}
}

func TestRuleR5AdaptersDoNotImportInternal(t *testing.T) {
	m := testManifest()
	m.Legacy = []legacyEntry{{Package: "internal/policy", Target: "gate"}}
	g := makeGraph(map[string][]string{
		"cmd/tool":        {"internal/policy"},
		"internal/policy": {},
	})
	_, findings, _ := analyse(t, m, g)
	if got := ruleFor(t, findings, "cmd/tool", "internal/policy"); got != "R5" {
		t.Errorf("cmd -> internal: got %q, want R5", got)
	}
}

func TestUnclassifiedPackages(t *testing.T) {
	g := makeGraph(map[string][]string{
		"pkg/mystery": {},
	})
	e, err := newEngine(testManifest(), g)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	if !reflect.DeepEqual(e.unclassified, []string{"pkg/mystery"}) {
		t.Fatalf("unclassified = %v", e.unclassified)
	}
	if got := unclassifiedRule("pkg/mystery"); got != "R6" {
		t.Errorf("pkg rule = %q, want R6", got)
	}
	if got := unclassifiedRule("internal/mystery"); got != "R7" {
		t.Errorf("outside-pkg rule = %q, want R7", got)
	}
}

func TestRuleR8ToolsAreLeaf(t *testing.T) {
	g := makeGraph(map[string][]string{
		"tools/checker": {"pkg/model"},
		"pkg/model":     {},
	})
	m := testManifest()
	m.Legacy = []legacyEntry{{Package: "pkg/model", Target: "contracts"}}
	_, findings, _ := analyse(t, m, g)
	if got := ruleFor(t, findings, "tools/checker", "pkg/model"); got != "R8" {
		t.Errorf("tools -> model: got %q, want R8", got)
	}
}

func TestBaselineAcceptsCurrentViolation(t *testing.T) {
	m := testManifest()
	m.Legacy = []legacyEntry{{Package: "pkg/assess", Target: "assess", Allow: []string{"pkg/gate"}}}
	g := makeGraph(map[string][]string{
		"pkg/assess": {"pkg/gate"},
		"pkg/gate":   {},
	})
	_, findings, stale := analyse(t, m, g)
	if len(findings) != 0 {
		t.Errorf("baselined edge still reported: %+v", findings)
	}
	if len(stale) != 0 {
		t.Errorf("unexpected stale entries: %v", stale)
	}
}

func TestBaselineDetectsNewViolation(t *testing.T) {
	m := testManifest()
	m.Legacy = []legacyEntry{{Package: "pkg/assess", Target: "assess", Allow: []string{"pkg/gate"}}}
	g := makeGraph(map[string][]string{
		"pkg/assess":     {"pkg/gate", "pkg/regulatory"},
		"pkg/gate":       {},
		"pkg/regulatory": {},
	})
	_, findings, _ := analyse(t, m, g)
	if got := ruleFor(t, findings, "pkg/assess", "pkg/regulatory"); got != "R2" {
		t.Errorf("new edge: got %q, want R2", got)
	}
}

func TestBaselineDetectsStaleEntry(t *testing.T) {
	m := testManifest()
	m.Legacy = []legacyEntry{{Package: "pkg/assess", Target: "assess", Allow: []string{"pkg/gate"}}}
	g := makeGraph(map[string][]string{
		"pkg/assess": {},
		"pkg/gate":   {},
	})
	_, _, stale := analyse(t, m, g)
	if len(stale) == 0 {
		t.Fatal("allow entry for a clean package was not reported as stale")
	}
}

func TestBaselineDetectsVanishedPackage(t *testing.T) {
	m := testManifest()
	m.Legacy = []legacyEntry{{Package: "pkg/removed", Target: "assess", Allow: []string{"pkg/gate"}}}
	g := makeGraph(map[string][]string{
		"pkg/assess": {},
		"pkg/gate":   {},
	})
	e, err := newEngine(m, g)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	e.computeFindings()
	_, stale := e.compareBaseline()
	if len(stale) == 0 {
		t.Fatal("vanished baseline package was not reported")
	}
}

func TestInitBaselineIsSortedAndComplete(t *testing.T) {
	m := testManifest()
	m.Legacy = []legacyEntry{
		{Package: "pkg/model", Target: "contracts"},
		{Package: "pkg/legacy", Target: "assess"},
	}
	g := makeGraph(map[string][]string{
		"pkg/assess": {"pkg/gate"},
		"pkg/legacy": {"pkg/gate", "pkg/ui"},
		"pkg/gate":   {},
		"pkg/model":  {},
		"pkg/ui":     {},
	})
	e, err := newEngine(m, g)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	e.computeFindings()
	entries := e.initLegacy()

	want := []legacyEntry{
		{Package: "pkg/assess", Target: "assess", Allow: []string{"pkg/gate"}},
		{Package: "pkg/legacy", Target: "assess", Allow: []string{"pkg/gate", "pkg/ui"}},
		{Package: "pkg/model", Target: "contracts", Allow: []string{}},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("initLegacy() = %#v, want %#v", entries, want)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "modules.yaml")
	m := testManifest()
	m.Legacy = []legacyEntry{{Package: "pkg/assess", Target: "assess", Allow: []string{"pkg/gate"}}}
	if err := writeManifest(path, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}
	got, err := loadManifest(path)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	wantYAML, err := yaml.Marshal(m)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	gotYAML, err := yaml.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	if !bytes.Equal(wantYAML, gotYAML) {
		t.Fatalf("round trip differs:\nwant:\n%s\ngot:\n%s", wantYAML, gotYAML)
	}
}

func TestManifestRejectsOverlappingModules(t *testing.T) {
	m := testManifest()
	m.Modules["nested"] = moduleSpec{Packages: []string{"pkg/assess/nested"}}
	if err := checkPrefixes(m.Modules); err == nil {
		t.Fatal("overlapping module prefixes were accepted")
	}
}

func TestScanGraphFindsRepositoryImports(t *testing.T) {
	g, err := scanGraph("../..", "")
	if err != nil {
		t.Fatalf("scanGraph: %v", err)
	}
	gate := g["pkg/gate"]
	if gate == nil {
		t.Fatal("pkg/gate is missing from the graph")
	}
	if _, ok := gate.Imports["pkg/ui"]; !ok {
		t.Errorf("pkg/gate imports = %v, want pkg/ui", gate.Imports)
	}
	model := g["pkg/model"]
	if model == nil {
		t.Fatal("pkg/model is missing from the graph")
	}
	if len(model.Imports) != 0 {
		t.Errorf("pkg/model imports = %v, want none", model.Imports)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWritefSurvivesWriteError(t *testing.T) {
	var buf bytes.Buffer
	writef(&buf, "value=%d", 7)
	if buf.String() != "value=7" {
		t.Errorf("writef wrote %q", buf.String())
	}
	writef(failingWriter{}, "discarded")
}

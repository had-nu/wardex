// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
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
	alpha := counts["github.com/had-nu/wardex/v2/pkg/alpha"]
	if alpha != [2]int{10, 4} {
		t.Errorf("alpha = %v, want {10 4}", alpha)
	}
	beta := counts["github.com/had-nu/wardex/v2/pkg/beta"]
	if beta != [2]int{3, 3} {
		t.Errorf("beta = %v, want {3 3}", beta)
	}
}

func TestParseProfileRejectsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(path, []byte("mode: set\nnot-a-block\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseProfile(path); err == nil {
		t.Fatal("malformed line was accepted")
	}
}

func TestBuildReportIncludesUntestedPackages(t *testing.T) {
	packages := []string{"pkg/alpha", "pkg/beta", "pkg/gamma"}
	counts := map[string][2]int{
		"pkg/alpha": {10, 5},
		"pkg/gamma": {4, 1},
	}
	rep := buildReport(packages, counts)

	if len(rep.Packages) != 3 {
		t.Fatalf("rows = %d, want 3", len(rep.Packages))
	}
	if !rep.Packages[1].Untested || rep.Packages[1].Statements != 0 {
		t.Errorf("beta = %+v, want untested", rep.Packages[1])
	}
	if rep.Packages[0].Percent != 50 {
		t.Errorf("alpha percent = %v, want 50", rep.Packages[0].Percent)
	}
	if rep.Total.Statements != 14 || rep.Total.Covered != 6 {
		t.Errorf("total = %+v, want 14/6", rep.Total)
	}
}

func TestBuildReportKeepsProfilePackagesMissingFromGoList(t *testing.T) {
	rep := buildReport([]string{"pkg/alpha"}, map[string][2]int{
		"pkg/alpha": {10, 10},
		"pkg/gone":  {2, 2},
	})
	if len(rep.Packages) != 2 || rep.Packages[1].Package != "pkg/gone" {
		t.Fatalf("rows = %+v, want the stale profile package included", rep.Packages)
	}
}

func TestRenderMarkdown(t *testing.T) {
	rep := report{
		Packages: []packageCoverage{
			{Package: "pkg/alpha", Statements: 10, Covered: 5, Percent: 50},
			{Package: "pkg/beta", Untested: true},
		},
		Total: packageCoverage{Statements: 10, Covered: 5, Percent: 50},
	}
	out := renderMarkdown(rep)
	for _, want := range []string{
		"| Package | Statements | Covered | Coverage |",
		"| `pkg/alpha` | 10 | 5 | 50.0% |",
		"| `pkg/beta` | 0 | 0 | untested |",
		"| **Total** | 10 | 5 | 50.0% |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testManifest = `version: 1
language: en-GB
specs:
  - file: SPEC-M0-baseline.md
    id: M0
    title: "Baseline"
    status: active
    owner: had-nu
    base: "main @ abc"
`

const testGlossary = `version: 1
language: en-GB
reserved:
  - package
terms:
  - term: package
    definition: A Go package.
forbidden:
  - pacote
`

const validSpec = `# SPEC-M0 — Baseline: test

Wardex · draft 1 · 20 October 2026 · base: main @ abc

## 1. Purpose

Test purpose.

## 2. Scope

Test scope.

## 3. Inherited decisions

| # | Decision |
| --- | --- |
| D1 | Test decision. |

## 4. Prerequisites

- **M0-P0.1** Do the thing.

## 5. Components

| Field | Value |
| --- | --- |
| Inputs | x |
| Outputs | x |
| Public API | x |
| Allowed dependencies | x |
| Absorbed packages | x |
| Absorbed commands | x |
| Branch | x |
| Estimate | x |

### 5.1 Component

- R1 A rule.

## 6. Error model

Test error model.

## 7. Standalone use

Test use.

## 8. Test plan

Test plan.

## 9. Migration plan

| Step | Work | Acceptance criterion |
| --- | --- | --- |
| M0-P1 | Work. | Done. |

## 10. Definition of done

Test done.

## 11. Risks

Test risk.

## 12. Not verified

Pending.
`

var validTemplate = strings.Replace(
	validSpec,
	"# SPEC-M0 — Baseline: test\n\nWardex · draft 1 · 20 October 2026 · base: main @ abc",
	"# SPEC-M<n> — <Name>\n\nWardex · draft <version> · <date> · base: <ref>",
	1,
)

func sandbox(t *testing.T, manifest, glossary, spec string) string {
	t.Helper()

	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("doc/specs/specs.yaml", manifest)
	write("doc/specs/glossary.yaml", glossary)
	write("doc/specs/SPEC-M0-baseline.md", spec)
	write("doc/specs/TEMPLATE_module.md", validTemplate)
	return root
}

func rules(violations []violation) []string {
	out := make([]string, 0, len(violations))
	for _, v := range violations {
		out = append(out, v.Rule)
	}
	return out
}

func hasRule(violations []violation, rule string) bool {
	for _, v := range violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func TestCheckPassesAValidSpec(t *testing.T) {
	root := sandbox(t, testManifest, testGlossary, validSpec)

	rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(rep.Violations) != 0 {
		t.Fatalf("violations = %v, want none", rep.Violations)
	}
	if len(rep.Unclassified) != 0 {
		t.Fatalf("unclassified = %v, want none", rep.Unclassified)
	}
	if rep.Checked != 2 {
		t.Fatalf("checked %d specs, want 2", rep.Checked)
	}
}

// TestCheckAcceptsASpecInASubdirectory guards the v3 layout: an inventory path
// may carry a directory, and the name rule applies to the file name alone.
func TestCheckAcceptsASpecInASubdirectory(t *testing.T) {
	manifest := `version: 1
language: en-GB
specs:
  - file: v3/SPEC-M0-baseline.md
    id: M0
    title: "Baseline"
    status: active
    owner: had-nu
    base: "main @ abc"
`
	root := sandbox(t, manifest, testGlossary, validSpec)
	flat := filepath.Join(root, "doc", "specs", "SPEC-M0-baseline.md")
	if err := os.Remove(flat); err != nil {
		t.Fatalf("remove flat spec: %v", err)
	}
	nested := filepath.Join(root, "doc", "specs", "v3")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatalf("mkdir v3: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "SPEC-M0-baseline.md"), []byte(validSpec), 0o600); err != nil {
		t.Fatalf("write nested spec: %v", err)
	}

	rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(rep.Violations) != 0 {
		t.Fatalf("violations = %v, want none", rep.Violations)
	}
	if len(rep.Unclassified) != 0 {
		t.Fatalf("unclassified = %v, want none", rep.Unclassified)
	}
}

func TestCheckFindsOneViolationPerRule(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		rule string
	}{
		{"missing section", "## 12. Not verified\n\nPending.\n", "", "SPEC-SECTION"},
		{"missing card row", "| Inputs | x |\n", "", "SPEC-CARD"},
		{"missing byline", "Wardex · draft 1 · 20 October 2026 · base: main @ abc\n", "", "SPEC-BYLINE"},
		{"bad title", "# SPEC-M0 — Baseline: test", "# Baseline", "SPEC-TITLE"},
		{"duplicate id", "| D1 | Test decision. |", "| D1 | Test decision. |\n| D1 | Again. |", "SPEC-ID"},
		{"forbidden term", "Pending.", "The pacote.", "SPEC-LANG"},
		{"broken cross-reference", "Pending.", "See M0#R9.", "SPEC-XREF"},
		{"unknown spec reference", "Pending.", "See M9#R1.", "SPEC-XREF"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := strings.Replace(validSpec, tc.old, tc.new, 1)
			if spec == validSpec {
				t.Fatalf("fixture does not contain %q", tc.old)
			}
			root := sandbox(t, testManifest, testGlossary, spec)

			rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if !hasRule(rep.Violations, tc.rule) {
				t.Fatalf("violations = %v, want rule %s", rules(rep.Violations), tc.rule)
			}
		})
	}
}

func TestCheckIgnoresCodeAndGlossaryTable(t *testing.T) {
	spec := strings.Replace(validSpec, "Pending.", "The `pacote` term is forbidden.\n\n**Glossary.**\n\n| Term | Avoid |\n| --- | --- |\n| package | pacote |\n\n**Tool.**\n\nThe table is definitional.", 1)
	root := sandbox(t, testManifest, testGlossary, spec)

	rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if hasRule(rep.Violations, "SPEC-LANG") {
		t.Fatalf("violations = %v, want no language violation", rep.Violations)
	}
}

func TestCheckFindsAnUnlistedSpec(t *testing.T) {
	root := sandbox(t, testManifest, testGlossary, validSpec)
	full := filepath.Join(root, "doc", "specs", "SPEC-M9-extra.md")
	if err := os.WriteFile(full, []byte("# SPEC-M9 — Extra\n"), 0o600); err != nil {
		t.Fatalf("write extra spec: %v", err)
	}

	rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(rep.Unclassified) != 1 {
		t.Fatalf("unclassified = %v, want exactly one", rep.Unclassified)
	}
	if rep.Unclassified[0].Rule != "SPEC-INVENTORY" {
		t.Fatalf("rule = %q, want SPEC-INVENTORY", rep.Unclassified[0].Rule)
	}
}

func TestLegacySpecNeedsAnAbstract(t *testing.T) {
	manifest := testManifest + `  - file: SPEC-old.md
    id: old
    title: "Old"
    status: legacy-pt
`
	root := sandbox(t, manifest, testGlossary, validSpec)
	if err := os.WriteFile(filepath.Join(root, "doc", "specs", "SPEC-old.md"), []byte("# Old\n"), 0o600); err != nil {
		t.Fatalf("write legacy spec: %v", err)
	}

	rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !hasRule(rep.Violations, "SPEC-ABSTRACT") {
		t.Fatalf("violations = %v, want SPEC-ABSTRACT", rules(rep.Violations))
	}
}

func TestActiveSpecNeedsOwnerAndBase(t *testing.T) {
	manifest := `version: 1
language: en-GB
specs:
  - file: SPEC-M0-baseline.md
    id: M0
    title: "Baseline"
    status: active
`
	root := sandbox(t, manifest, testGlossary, validSpec)

	if _, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml"); err == nil {
		t.Fatal("check accepted an active spec without owner and base")
	}
}

func TestCheckRequiresATemplate(t *testing.T) {
	root := sandbox(t, testManifest, testGlossary, validSpec)
	if err := os.Remove(filepath.Join(root, "doc", "specs", "TEMPLATE_module.md")); err != nil {
		t.Fatalf("remove template: %v", err)
	}

	rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !hasRule(rep.Violations, "SPEC-TEMPLATE") {
		t.Fatalf("violations = %v, want SPEC-TEMPLATE", rules(rep.Violations))
	}
}

func TestCheckRejectsADuplicateManifestID(t *testing.T) {
	manifest := testManifest + `  - file: SPEC-M1-other.md
    id: M0
    title: "Other"
    status: active
    owner: had-nu
    base: "main @ abc"
`
	root := sandbox(t, manifest, testGlossary, validSpec)

	if _, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml"); err == nil {
		t.Fatal("check accepted a duplicate manifest id")
	}
}

func TestContainsWord(t *testing.T) {
	cases := []struct {
		text string
		word string
		want bool
	}{
		{"the pacote is", "pacote", true},
		{"pacotes", "pacote", false},
		{"módulo", "módulo", true},
		{"Módulo", "módulo", true},
		{"linha de base", "linha de base", true},
		{"linha de base extra", "linha de base", true},
		{"linha de bases", "linha de base", false},
		{"a boundary check here", "boundary check", true},
	}
	for _, tc := range cases {
		if got := containsWord(tc.text, tc.word); got != tc.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", tc.text, tc.word, got, tc.want)
		}
	}
}

// TestCheckOnThisRepository is the reason the tool runs in CI: the active spec
// and the template must hold together at the commit that runs the check.
func TestCheckOnThisRepository(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))

	rep, err := check(root, "doc/specs/specs.yaml", "doc/specs/glossary.yaml")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if rep.Checked == 0 {
		t.Fatal("checked no specs; the paths are wrong")
	}
	for _, v := range rep.Violations {
		t.Errorf("%s", v)
	}
	for _, v := range rep.Unclassified {
		t.Errorf("%s", v)
	}
}

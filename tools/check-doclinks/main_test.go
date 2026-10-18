// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes files into a throwaway tree and returns its root.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

func TestCheckFindsABrokenLink(t *testing.T) {
	root := fixture(t, map[string]string{
		"README.md": "[good](doc/a.md) [bad](doc/missing.md)",
		"doc/a.md":  "# A\n",
	})

	broken, scanned, links, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if scanned != 2 {
		t.Fatalf("scanned %d documents, want 2", scanned)
	}
	if links != 2 {
		t.Fatalf("counted %d relative links, want 2", links)
	}
	if len(broken) != 1 {
		t.Fatalf("broken = %+v, want exactly one", broken)
	}
	if broken[0].Target != "doc/missing.md" {
		t.Fatalf("broken target = %q, want doc/missing.md", broken[0].Target)
	}
	if broken[0].Document != "README.md" {
		t.Fatalf("blamed document = %q, want README.md", broken[0].Document)
	}
}

// TestCheckResolvesRelativeToTheDocument covers the mistake this tool exists for:
// a link written as if the document sat at the repository root. From doc/a.md,
// "README.md" is doc/README.md, which does not exist.
func TestCheckResolvesRelativeToTheDocument(t *testing.T) {
	root := fixture(t, map[string]string{
		"README.md": "# Root\n",
		"doc/a.md":  "[root](README.md)  [right](../README.md)\n",
	})

	broken, _, _, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(broken) != 1 {
		t.Fatalf("broken = %+v, want one", broken)
	}
	if broken[0].Target != "README.md" {
		t.Fatalf("broken target = %q, want README.md", broken[0].Target)
	}
	if !strings.HasSuffix(broken[0].Document, "doc/a.md") {
		t.Fatalf("blamed document = %q, want doc/a.md", broken[0].Document)
	}
}

func TestCheckIgnoresTargetsThatAreNotRepositoryPaths(t *testing.T) {
	body := strings.Join([]string{
		"[a](https://example.invalid/x)",
		"[b](http://example.invalid/y)",
		"[c](mailto:someone@example.invalid)",
		"[d](#anchor-in-the-same-document)",
		"[e](/absolute/path)",
		"[f](//protocol-relative.invalid/x)",
	}, "\n")

	root := fixture(t, map[string]string{"doc.md": body + "\n"})

	broken, _, links, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if links != 0 {
		t.Fatalf("counted %d relative links, want 0", links)
	}
	if len(broken) != 0 {
		t.Fatalf("broken = %+v, want none", broken)
	}
}

func TestCheckIgnoresAnchorsAndQueriesOnRealTargets(t *testing.T) {
	root := fixture(t, map[string]string{
		"README.md": "[anchor](doc/a.md#section) [query](doc/a.md?v=2)\n",
		"doc/a.md":  "# A\n",
	})

	broken, _, links, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if links != 2 {
		t.Fatalf("counted %d links, want 2", links)
	}
	if len(broken) != 0 {
		t.Fatalf("broken = %+v, want none", broken)
	}
}

// TestCheckAcceptsADirectory checks that a link to a folder is not reported. A
// folder link is legitimate and every viewer resolves it.
func TestCheckAcceptsADirectory(t *testing.T) {
	root := fixture(t, map[string]string{
		"README.md": "[folder](doc)\n",
		"doc/a.md":  "# A\n",
	})

	broken, _, _, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(broken) != 0 {
		t.Fatalf("broken = %+v, want none", broken)
	}
}

// TestCheckSkipsBuildOutput checks that a broken link inside dist/ does not fail
// the build. dist/ holds a copy of the tree that is never on a merge path.
func TestCheckSkipsBuildOutput(t *testing.T) {
	root := fixture(t, map[string]string{
		"README.md":      "# Root\n",
		"dist/README.md": "[gone](nowhere.md)\n",
	})

	broken, scanned, _, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(broken) != 0 {
		t.Fatalf("broken = %+v, want none", broken)
	}
	if scanned != 1 {
		t.Fatalf("scanned %d documents, want 1", scanned)
	}
}

func TestIsRelative(t *testing.T) {
	cases := map[string]bool{
		"doc/a.md":                 true,
		"../README.md":             true,
		"./a.md":                   true,
		"a.md#section":             true,
		"https://example.invalid":  false,
		"http://example.invalid":   false,
		"mailto:a@example.invalid": false,
		"#anchor":                  false,
		"/abs":                     false,
		"//host/abs":               false,
		"":                         false,
		"C:/windows/path.md":       false,
	}
	for target, want := range cases {
		if got := isRelative(target); got != want {
			t.Errorf("isRelative(%q) = %v, want %v", target, got, want)
		}
	}
}

// TestCheckOnThisRepositoryIsClean is the reason the tool runs in CI: the
// documentation must hold together at the commit that runs the check.
func TestCheckOnThisRepositoryIsClean(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))

	broken, scanned, links, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if scanned == 0 {
		t.Fatal("scanned no documents; the walk found nothing")
	}
	if links == 0 {
		t.Fatal("counted no links; the pattern matched nothing")
	}
	for _, b := range broken {
		t.Errorf("%s links to %s, which does not exist", b.Document, b.Target)
	}
}

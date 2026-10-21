// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadFrameworkDistinguishesMissingFromEmpty checks that the two failures a
// caller can act on are not reported the same way.
//
// Removing a framework leaves a path behind in a script or a CI job. "no .yml or
// .yaml files found in ..." reads as an empty directory and sends the reader to
// look at the wrong thing; the path does not exist. The message has to say which
// of the two it is.
func TestLoadFrameworkDistinguishesMissingFromEmpty(t *testing.T) {
	root := t.TempDir()

	_, err := LoadFramework(filepath.Join(root, "does-not-exist"))
	if err == nil {
		t.Fatal("LoadFramework of a missing directory returned no error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a missing directory reported as %q; the message does not say the path is absent", err)
	}

	empty := filepath.Join(root, "empty")
	if mkErr := os.Mkdir(empty, 0o750); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	_, err = LoadFramework(empty)
	if err == nil {
		t.Fatal("LoadFramework of an empty directory returned no error")
	}
	if !strings.Contains(err.Error(), "no .yml or .yaml files") {
		t.Errorf("an empty directory reported as %q; the message does not say it holds no files", err)
	}
	if strings.Contains(err.Error(), "does not exist") {
		t.Errorf("an empty directory reported as %q; that message means the path is absent", err)
	}
}

// TestLoadFrameworkStillLoadsARealDirectory guards the change against breaking
// the case that works.
//
// The loader reads through the path guard, which confines access to the working
// directory, so the fixture has to live under it rather than in a temporary
// directory elsewhere on the filesystem.
func TestLoadFrameworkStillLoadsARealDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	body := "framework: \"nis2\"\nversion: \"1\"\ndomain: \"cyber_hygiene\"\ncontrols:\n  - id: \"NIS2.21.2.a\"\n    title: \"Policies on Risk Analysis\"\n    status: \"compliant\"\n"
	for _, name := range []string{"a.yml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	got, err := LoadFramework(".")
	if err != nil {
		t.Fatalf("LoadFramework: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d domain files, want 2", len(got))
	}
}

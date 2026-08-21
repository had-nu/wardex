// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzValidateInputPath exercises the path validation guards with arbitrary
// inputs. Invariants:
//   - a successfully resolved path never escapes the base directory;
//   - null-byte paths and overlong paths are always rejected;
//   - stdin ("-") is the only "path" that may resolve to itself.
func FuzzValidateInputPath(f *testing.F) {
	f.Add([]byte("normal.yaml"))
	f.Add([]byte("sub/dir/file.yaml"))
	f.Add([]byte("../escape.yaml"))
	f.Add([]byte("/etc/passwd"))
	f.Add([]byte("a\x00b"))
	f.Add([]byte(strings.Repeat("x", 5000)))
	f.Add([]byte(".."))
	f.Add([]byte("."))
	f.Add([]byte("-"))
	f.Add([]byte("./ok.yaml"))
	f.Add([]byte("..//../double.yaml"))

	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		path := string(data)

		resolved, err := ValidateInputPath(base, path)
		if err == nil {
			if resolved != "-" {
				rel, rerr := filepath.Rel(base, resolved)
				if rerr != nil {
					t.Fatalf("resolved path is not relative to base: %q -> %q", path, resolved)
				}
				if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					t.Fatalf("resolved path escapes base: %q -> %q", path, resolved)
				}
			}
		}

		if strings.ContainsRune(path, 0) && err == nil {
			t.Fatalf("null-byte path accepted: %q", path)
		}
		if len(path) > maxPathLen && err == nil {
			t.Fatalf("overlong path accepted: %d bytes", len(path))
		}
	})
}

// FuzzValidateOutputPath checks the additional output restrictions: paths
// resolving into /proc, /sys and /dev must always be rejected.
func FuzzValidateOutputPath(f *testing.F) {
	f.Add([]byte("out.json"))
	f.Add([]byte("../../proc/self/mem"))
	f.Add([]byte("../../sys/kernel"))
	f.Add([]byte("../../dev/null"))
	f.Add([]byte("/dev/null"))

	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		path := string(data)

		resolved, err := ValidateOutputPath(base, path)
		if err == nil {
			for _, prefix := range []string{"/proc/", "/sys/", "/dev/"} {
				if strings.HasPrefix(resolved, prefix) {
					t.Fatalf("output path resolves into pseudo-filesystem: %q -> %q", path, resolved)
				}
			}
			rel, rerr := filepath.Rel(base, resolved)
			if rerr != nil {
				t.Fatalf("resolved output path is not relative to base: %q -> %q", path, resolved)
			}
			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("output path escapes base: %q -> %q", path, resolved)
			}
		}
	})
}

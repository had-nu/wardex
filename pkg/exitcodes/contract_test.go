// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package exitcodes

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// codeContract is the numeric contract of every exit code. It is the published
// interface that CI pipelines and doc/operations/EXIT_CODES.md depend on, so it
// must never drift.
var codeContract = map[string]int{
	"OK":                0,
	"GenericError":      1,
	"IntegrityFailure":  3,
	"StoreInconsistent": 4,
	"ExpiringSoon":      5,
	"FreshnessAdvisory": 6,
	"GateBlocked":       10,
	"ComplianceFail":    11,
	"ActivelyExploited": 12,
	"DuplicateRelease":  13,
}

// posixReserved codes must never be produced by Wardex.
var posixReserved = map[int]string{
	2:   "misuse of shell builtins",
	126: "command invoked cannot execute",
	127: "command not found",
}

// declaredCodes parses exitcodes.go and returns every untyped integer constant
// declared in the package, keyed by name.
//
// The invariants in this file used to be enforced over hand-copied lists that
// covered 6 of 10 codes; adding a constant without editing the lists left the
// "no POSIX collision" and "no collision" invariants silently unenforced.
// Deriving the real set from source removes that failure mode: a new constant
// cannot escape the checks.
func declaredCodes(t *testing.T) map[string]int {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "exitcodes.go", nil, 0)
	if err != nil {
		t.Fatalf("parse exitcodes.go: %v", err)
	}

	found := make(map[string]int)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				continue
			}
			value, err := strconv.Atoi(lit.Value)
			if err != nil {
				t.Fatalf("const %s has non-integer value %s", vs.Names[0].Name, lit.Value)
			}
			found[vs.Names[0].Name] = value
		}
	}

	if len(found) == 0 {
		t.Fatal("no integer constants found in exitcodes.go; the parser no longer matches the source")
	}
	return found
}

// TestContractMatchesSource fails when a constant is added, removed or renamed
// without updating the published contract.
func TestContractMatchesSource(t *testing.T) {
	source := declaredCodes(t)

	var missing, extra []string
	for name := range codeContract {
		if _, ok := source[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range source {
		if _, ok := codeContract[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("contract names removed from exitcodes.go: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("constants added to exitcodes.go without a contract entry: %v\n"+
			"add them to codeContract, then document them in doc/operations/EXIT_CODES.md", extra)
	}
	if len(missing) == 0 && len(extra) == 0 && len(source) != len(codeContract) {
		t.Errorf("contract has %d entries, source has %d", len(codeContract), len(source))
	}
}

// TestContractValuesAreStable pins the numeric values. These are the numbers CI
// pipelines branch on, so a silent change is a breaking change.
func TestContractValuesAreStable(t *testing.T) {
	source := declaredCodes(t)
	for name, want := range codeContract {
		got, ok := source[name]
		if !ok {
			t.Errorf("%s is not declared in exitcodes.go", name)
			continue
		}
		if got != want {
			t.Errorf("%s = %d, want %d (this is a breaking change for CI consumers)", name, got, want)
		}
	}
}

// TestNoPOSIXReservedCode enforces the reserved-code invariant over every
// declared constant, not a copied subset.
func TestNoPOSIXReservedCode(t *testing.T) {
	for name, code := range declaredCodes(t) {
		if reason, reserved := posixReserved[code]; reserved {
			t.Errorf("exit code %s=%d collides with POSIX reserved code: %s", name, code, reason)
		}
		if code >= 128 && code <= 255 {
			t.Errorf("exit code %s=%d falls in the signal range 128-255", name, code)
		}
	}
}

// TestNoCollisions enforces uniqueness over every declared constant.
func TestNoCollisions(t *testing.T) {
	seen := make(map[int]string)
	for name, code := range declaredCodes(t) {
		if other, taken := seen[code]; taken {
			t.Errorf("exit codes %s and %s both map to %d", other, name, code)
			continue
		}
		seen[code] = name
	}

	if len(seen) != len(codeContract) {
		t.Errorf("expected %d unique exit codes, got %d", len(codeContract), len(seen))
	}
}

// TestGateBlockedNotTwo is the original regression guard, kept as an explicit
// named case because the bug it guards is the one most likely to recur.
func TestGateBlockedNotTwo(t *testing.T) {
	if GateBlocked == 2 {
		t.Error("GateBlocked must not be 2 (POSIX reserved for shell builtin misuse)")
	}
}

// TestDocumentedExitCodesAreImplemented checks that every code named in the
// operations documentation has a constant behind it. The document is the
// contract operators read; a code described there but never returned is worse
// than undocumented.
func TestDocumentedExitCodesAreImplemented(t *testing.T) {
	// code -> the value documented in doc/operations/EXIT_CODES.md
	documented := map[string]string{
		"OK":                "0",
		"GenericError":      "1",
		"IntegrityFailure":  "3",
		"StoreInconsistent": "4",
		"ExpiringSoon":      "5",
		"FreshnessAdvisory": "6",
		"GateBlocked":       "10",
		"ComplianceFail":    "11",
		"ActivelyExploited": "12",
		"DuplicateRelease":  "13",
	}

	source := declaredCodes(t)
	for name, codeString := range documented {
		want, err := strconv.Atoi(codeString)
		if err != nil {
			t.Fatalf("bad documented code %q for %s", codeString, name)
		}
		got, ok := source[name]
		if !ok {
			t.Errorf("documented exit code %s=%s has no constant", name, codeString)
			continue
		}
		if got != want {
			t.Errorf("%s = %d, but the documentation says %s", name, got, codeString)
		}
	}

	if len(documented) != len(codeContract) {
		t.Errorf("documentation covers %d codes, contract has %d", len(documented), len(codeContract))
	}
}

// TestExitCodesAreOrderedBySeverity documents the numbering contract: generic
// errors below 3, policy decisions at 10 and above.
func TestExitCodesAreOrderedBySeverity(t *testing.T) {
	if GenericError != 1 {
		t.Errorf("GenericError = %d, want 1", GenericError)
	}
	for name, code := range declaredCodes(t) {
		switch name {
		case "OK", "GenericError":
			continue
		}
		if code < 3 {
			t.Errorf("%s = %d, want >= 3 so it does not collide with generic errors", name, code)
		}
	}
}

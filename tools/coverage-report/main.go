// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command coverage-report turns a Go coverprofile into a per-package table.
//
// The coverage profile lists only packages that produced coverage lines.
// Packages without tests are absent, which is exactly the set the ratchet has
// to keep at floor zero instead of silently dropping. The report therefore
// merges the profile with `go list ./...`, and marks a package with no
// statements as untested.
//
// Usage:
//
//	go run ./tools/coverage-report -profile coverage.out -out coverage.md
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// packageCoverage is one row of the report.
type packageCoverage struct {
	Package    string  `json:"package"`
	Statements int     `json:"statements"`
	Covered    int     `json:"covered"`
	Percent    float64 `json:"percent"`
	Untested   bool    `json:"untested,omitempty"`
}

type report struct {
	Packages []packageCoverage `json:"packages"`
	Total    packageCoverage   `json:"total"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("coverage-report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profilePath := fs.String("profile", "coverage.out", "Go coverprofile to read")
	outPath := fs.String("out", "", "write Markdown to this file instead of stdout")
	jsonPath := fs.String("json", "", "write JSON to this file")
	repoDir := fs.String("repo", ".", "repository root")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	counts, err := parseProfile(*profilePath)
	if err != nil {
		writef(stderr, "coverage-report: %v\n", err)
		return 2
	}
	packages, err := listPackages(*repoDir)
	if err != nil {
		writef(stderr, "coverage-report: %v\n", err)
		return 2
	}
	rep := buildReport(packages, counts)

	if *jsonPath != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			writef(stderr, "coverage-report: %v\n", err)
			return 2
		}
		if err := os.WriteFile(*jsonPath, append(data, '\n'), 0o600); err != nil {
			writef(stderr, "coverage-report: %v\n", err)
			return 2
		}
	}

	markdown := renderMarkdown(rep)
	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(markdown), 0o600); err != nil {
			writef(stderr, "coverage-report: %v\n", err)
			return 2
		}
		return 0
	}
	if _, err := io.WriteString(stdout, markdown); err != nil {
		writef(stderr, "coverage-report: %v\n", err)
		return 2
	}
	return 0
}

// parseProfile aggregates statement counts per package. The coverprofile
// format is one block per line: file:start,end statements count.
func parseProfile(path string) (map[string][2]int, error) {
	data, err := os.ReadFile(path) // #nosec G304 — the coverprofile path is supplied on the command line
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	counts := make(map[string][2]int)
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: expected 3 fields, got %d", path, lineNo+1, len(fields))
		}
		colon := strings.LastIndex(fields[0], ":")
		if colon < 0 {
			return nil, fmt.Errorf("%s:%d: malformed block %q", path, lineNo+1, fields[0])
		}
		file := fields[0][:colon]
		pkg := filepath.ToSlash(filepath.Dir(file))
		statements, err := strconv.Atoi(fields[1])
		if err != nil || statements < 0 {
			return nil, fmt.Errorf("%s:%d: invalid statement count %q", path, lineNo+1, fields[1])
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil || count < 0 {
			return nil, fmt.Errorf("%s:%d: invalid execution count %q", path, lineNo+1, fields[2])
		}
		row := counts[pkg]
		row[0] += statements
		if count > 0 {
			row[1] += statements
		}
		counts[pkg] = row
	}
	return counts, nil
}

// listPackages returns the repository-relative import paths of the main
// module, so untested packages appear in the table.
func listPackages(repoDir string) ([]string, error) {
	var stdout, stderr bytes.Buffer
	// #nosec G204 -- the command and flags are literals; repoDir is the local
	// repository root supplied to a development tool.
	cmd := exec.Command("go", "list", "./...")
	cmd.Dir = repoDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var packages []string
	for line := range strings.SplitSeq(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		packages = append(packages, line)
	}
	if len(packages) == 0 {
		return nil, errors.New("go list returned no packages")
	}
	return packages, nil
}

// buildReport merges profile counts with the package list. A profile package
// that go list no longer reports is kept: a stale profile should be visible in
// the table, not silently dropped.
func buildReport(packages []string, counts map[string][2]int) report {
	seen := make(map[string]bool, len(packages))
	var rows []packageCoverage
	total := packageCoverage{Package: "Total"}
	for _, pkg := range packages {
		seen[pkg] = true
		row := packageCoverage{Package: pkg}
		if c, ok := counts[pkg]; ok {
			row.Statements, row.Covered = c[0], c[1]
		}
		if row.Statements == 0 {
			row.Untested = true
		} else {
			row.Percent = 100 * float64(row.Covered) / float64(row.Statements)
		}
		total.Statements += row.Statements
		total.Covered += row.Covered
		rows = append(rows, row)
	}
	for pkg, c := range counts {
		if !seen[pkg] {
			row := packageCoverage{Package: pkg, Statements: c[0], Covered: c[1]}
			if row.Statements > 0 {
				row.Percent = 100 * float64(row.Covered) / float64(row.Statements)
			}
			total.Statements += row.Statements
			total.Covered += row.Covered
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Package < rows[j].Package })
	if total.Statements > 0 {
		total.Percent = 100 * float64(total.Covered) / float64(total.Statements)
	}
	return report{Packages: rows, Total: total}
}

func renderMarkdown(rep report) string {
	var b strings.Builder
	b.WriteString("# Coverage per package\n\n")
	b.WriteString("| Package | Statements | Covered | Coverage |\n")
	b.WriteString("| --- | ---: | ---: | ---: |\n")
	for _, row := range rep.Packages {
		coverage := fmt.Sprintf("%.1f%%", row.Percent)
		if row.Untested {
			coverage = "untested"
		}
		writef(&b, "| `%s` | %d | %d | %s |\n", row.Package, row.Statements, row.Covered, coverage)
	}
	writef(&b, "| **Total** | %d | %d | %.1f%% |\n", rep.Total.Statements, rep.Total.Covered, rep.Total.Percent)
	return b.String()
}

// writef reports to a diagnostic or report writer. A failure to write
// diagnostics cannot itself be reported, so the write ends without changing
// the tool's exit code.
func writef(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return
	}
}

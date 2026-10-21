// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command check-ratchet enforces the quality floors recorded in
// tools/baselines/.
//
// Coverage floors are per package and only rise. A package with no statements
// stays at floor zero with the untested marker, so moving code cannot make a
// package disappear from the baseline. #nosec annotations are counted only
// when they lack a rule code or a justification; the baseline holds the current
// debt and -update refuses to add to it.
//
// Usage:
//
//	go run ./tools/check-ratchet -coverage coverage.out
//	go run ./tools/check-ratchet -nosec
//	go run ./tools/check-ratchet -coverage coverage.out -nosec
//	go run ./tools/check-ratchet -coverage coverage.out -update
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const baselineVersion = 1

// coverageFloor is one package's floor. Untested records that the package has
// no statements at all, not that its coverage happens to be zero.
type coverageFloor struct {
	Floor    float64 `json:"floor"`
	Untested bool    `json:"untested,omitempty"`
}

type coverageBaseline struct {
	Version     int                      `json:"version"`
	GlobalFloor float64                  `json:"global_floor"`
	Packages    map[string]coverageFloor `json:"packages"`
}

type coverageRow struct {
	Statements int
	Covered    int
	Percent    float64
}

type nosecBaseline struct {
	Version     int            `json:"version"`
	Occurrences map[string]int `json:"occurrences"`
}

var nosecCodePattern = regexp.MustCompile(`G\d{3}`)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-ratchet", flag.ContinueOnError)
	fs.SetOutput(stderr)
	coveragePath := fs.String("coverage", "", "coverprofile to check")
	nosec := fs.Bool("nosec", false, "check #nosec annotations")
	update := fs.Bool("update", false, "rewrite the baselines, refusing decreases")
	repoDir := fs.String("repo", ".", "repository root")
	coverageBaselinePath := fs.String("coverage-baseline", "tools/baselines/coverage.json", "coverage baseline")
	nosecBaselinePath := fs.String("nosec-baseline", "tools/baselines/nosec.json", "#nosec baseline")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *coveragePath == "" && !*nosec {
		writeln(stderr, "check-ratchet: choose -coverage, -nosec or both")
		return 2
	}

	exit := 0
	if *coveragePath != "" {
		code := runCoverage(*coveragePath, *coverageBaselinePath, *repoDir, *update, stdout, stderr)
		if code != 0 {
			exit = code
		}
	}
	if *nosec {
		code := runNosec(*nosecBaselinePath, *repoDir, *update, stdout, stderr)
		if code != 0 && exit == 0 {
			exit = code
		}
	}
	return exit
}

func runCoverage(profilePath, baselinePath, repoDir string, update bool, stdout, stderr io.Writer) int {
	counts, err := parseProfile(profilePath)
	if err != nil {
		writef(stderr, "check-ratchet: %v\n", err)
		return 2
	}
	packages, err := listPackages(repoDir)
	if err != nil {
		writef(stderr, "check-ratchet: %v\n", err)
		return 2
	}
	current := currentCoverage(packages, counts)

	var baseline coverageBaseline
	if data, err := os.ReadFile(baselinePath); err == nil { // #nosec G304 — the baseline path is supplied on the command line
		if err := json.Unmarshal(data, &baseline); err != nil {
			writef(stderr, "check-ratchet: parse %s: %v\n", baselinePath, err)
			return 2
		}
		if baseline.Version != baselineVersion {
			writef(stderr, "check-ratchet: %s version %d is not %d\n", baselinePath, baseline.Version, baselineVersion)
			return 2
		}
	} else if !os.IsNotExist(err) {
		writef(stderr, "check-ratchet: read %s: %v\n", baselinePath, err)
		return 2
	} else if !update {
		writef(stderr, "check-ratchet: %s is missing; run with -update once\n", baselinePath)
		return 2
	}

	if update {
		return updateCoverage(baselinePath, baseline, current, stdout, stderr)
	}
	return checkCoverage(baseline, current, stdout, stderr)
}

func checkCoverage(baseline coverageBaseline, current map[string]coverageRow, stdout, stderr io.Writer) int {
	var regressions []string
	for _, pkg := range sortedKeys(current) {
		row := current[pkg]
		floor, ok := baseline.Packages[pkg]
		if !ok {
			// A new package starts at floor zero until the next update. It
			// cannot lower an existing floor, so it is not a regression.
			continue
		}
		if floor.Untested && row.Statements != 0 {
			regressions = append(regressions, fmt.Sprintf("%s now has %d statements; the baseline calls it untested", pkg, row.Statements))
			continue
		}
		if row.Statements == 0 && floor.Floor > 0 {
			regressions = append(regressions, fmt.Sprintf("%s has no statements; floor is %.1f%%", pkg, floor.Floor))
			continue
		}
		if row.Percent+0.05 < floor.Floor {
			regressions = append(regressions, fmt.Sprintf("%s %.1f%% is below the floor %.1f%%", pkg, row.Percent, floor.Floor))
		}
	}
	var stale []string
	for pkg := range baseline.Packages {
		if _, ok := current[pkg]; !ok {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)

	totalStatements, totalCovered := 0, 0
	for _, row := range current {
		totalStatements += row.Statements
		totalCovered += row.Covered
	}
	global := 0.0
	if totalStatements > 0 {
		global = 100 * float64(totalCovered) / float64(totalStatements)
	}
	if global+0.05 < baseline.GlobalFloor {
		regressions = append(regressions, fmt.Sprintf("global coverage %.1f%% is below the floor %.1f%%", global, baseline.GlobalFloor))
	}

	sort.Strings(regressions)
	for _, r := range regressions {
		writef(stdout, "coverage: %s\n", r)
	}
	for _, pkg := range stale {
		writef(stdout, "coverage: %s is in the baseline but no longer exists\n", pkg)
	}
	if len(regressions) > 0 {
		writef(stderr, "check-ratchet: %d coverage regression(s)\n", len(regressions))
		return 1
	}
	if len(stale) > 0 {
		writef(stderr, "check-ratchet: stale coverage baseline; run 'make ratchet-update'\n")
		return 2
	}
	writef(stdout, "coverage: %d packages, global %.1f%%, all floors met\n", len(current), global)
	return 0
}

func updateCoverage(path string, old coverageBaseline, current map[string]coverageRow, stdout, stderr io.Writer) int {
	next := coverageBaseline{
		Version:     baselineVersion,
		GlobalFloor: math.Max(old.GlobalFloor, 40),
		Packages:    make(map[string]coverageFloor, len(current)),
	}
	if next.GlobalFloor == 0 {
		next.GlobalFloor = 40
	}
	totalStatements, totalCovered := 0, 0
	for _, row := range current {
		totalStatements += row.Statements
		totalCovered += row.Covered
	}
	if totalStatements > 0 {
		global := 100 * float64(totalCovered) / float64(totalStatements)
		if global+0.05 < old.GlobalFloor {
			writef(stderr, "check-ratchet: global coverage %.1f%% is below the current floor %.1f%%; refusing to update\n", global, old.GlobalFloor)
			return 1
		}
	}

	var decreases []string
	for _, pkg := range sortedKeys(current) {
		row := current[pkg]
		floor := floorPercent(row.Percent)
		if row.Statements == 0 {
			floor = 0
		}
		if oldFloor, ok := old.Packages[pkg]; ok {
			if floor+0.05 < oldFloor.Floor {
				decreases = append(decreases, fmt.Sprintf("%s %.1f%% would lower the floor %.1f%%", pkg, floor, oldFloor.Floor))
				continue
			}
			floor = math.Max(floor, oldFloor.Floor)
		}
		next.Packages[pkg] = coverageFloor{Floor: floor, Untested: row.Statements == 0}
	}
	if len(decreases) > 0 {
		sort.Strings(decreases)
		for _, d := range decreases {
			writef(stdout, "coverage: %s\n", d)
		}
		writeln(stderr, "check-ratchet: refusing to lower a coverage floor")
		return 1
	}
	if err := writeJSON(path, next); err != nil {
		writef(stderr, "check-ratchet: %v\n", err)
		return 2
	}
	writef(stdout, "coverage: wrote %s (%d packages, global floor %.1f%%)\n", path, len(next.Packages), next.GlobalFloor)
	return 0
}

func runNosec(baselinePath, repoDir string, update bool, stdout, stderr io.Writer) int {
	current, err := scanNosec(repoDir)
	if err != nil {
		writef(stderr, "check-ratchet: %v\n", err)
		return 2
	}

	var baseline nosecBaseline
	baselineExists := false
	if data, err := os.ReadFile(baselinePath); err == nil { // #nosec G304 — the baseline path is supplied on the command line
		baselineExists = true
		if err := json.Unmarshal(data, &baseline); err != nil {
			writef(stderr, "check-ratchet: parse %s: %v\n", baselinePath, err)
			return 2
		}
		if baseline.Version != baselineVersion {
			writef(stderr, "check-ratchet: %s version %d is not %d\n", baselinePath, baseline.Version, baselineVersion)
			return 2
		}
	} else if !os.IsNotExist(err) {
		writef(stderr, "check-ratchet: read %s: %v\n", baselinePath, err)
		return 2
	} else if !update {
		writef(stderr, "check-ratchet: %s is missing; run with -update once\n", baselinePath)
		return 2
	}
	if baseline.Occurrences == nil {
		baseline.Occurrences = map[string]int{}
	}

	if update {
		var increases []string
		if baselineExists {
			for key, count := range current {
				if count > baseline.Occurrences[key] {
					increases = append(increases, fmt.Sprintf("%s: %d new unjustified annotation(s)", key, count-baseline.Occurrences[key]))
				}
			}
		}
		if len(increases) > 0 {
			sort.Strings(increases)
			for _, inc := range increases {
				writef(stdout, "nosec: %s\n", inc)
			}
			writeln(stderr, "check-ratchet: refusing to add unjustified #nosec annotations")
			return 1
		}
		next := nosecBaseline{Version: baselineVersion, Occurrences: current}
		if err := writeJSON(baselinePath, next); err != nil {
			writef(stderr, "check-ratchet: %v\n", err)
			return 2
		}
		writef(stdout, "nosec: wrote %s (%d unjustified annotation(s))\n", baselinePath, totalCount(current))
		return 0
	}

	var regressions, stale []string
	for key, count := range current {
		if count > baseline.Occurrences[key] {
			regressions = append(regressions, fmt.Sprintf("%s: %d > %d", key, count, baseline.Occurrences[key]))
		}
	}
	for key, count := range baseline.Occurrences {
		if current[key] < count {
			stale = append(stale, fmt.Sprintf("%s: %d < %d", key, current[key], count))
		}
	}
	sort.Strings(regressions)
	sort.Strings(stale)
	for _, r := range regressions {
		writef(stdout, "nosec: %s\n", r)
	}
	for _, s := range stale {
		writef(stdout, "nosec: baseline %s\n", s)
	}
	if len(regressions) > 0 {
		writef(stderr, "check-ratchet: unjustified #nosec annotations increased\n")
		return 1
	}
	if len(stale) > 0 {
		writef(stderr, "check-ratchet: stale #nosec baseline; run 'make ratchet-update'\n")
		return 2
	}
	writef(stdout, "nosec: %d unjustified annotation(s), baseline met\n", totalCount(current))
	return 0
}

// parseProfile aggregates statement counts per package.
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
		pkg := filepath.ToSlash(filepath.Dir(fields[0][:colon]))
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
		if line = strings.TrimSpace(line); line != "" {
			packages = append(packages, line)
		}
	}
	if len(packages) == 0 {
		return nil, errors.New("go list returned no packages")
	}
	return packages, nil
}

func currentCoverage(packages []string, counts map[string][2]int) map[string]coverageRow {
	rows := make(map[string]coverageRow, len(packages))
	for _, pkg := range packages {
		row := coverageRow{}
		if c, ok := counts[pkg]; ok {
			row.Statements, row.Covered = c[0], c[1]
		}
		if row.Statements > 0 {
			row.Percent = 100 * float64(row.Covered) / float64(row.Statements)
		}
		rows[pkg] = row
	}
	return rows
}

func floorPercent(p float64) float64 {
	return math.Floor(p*10) / 10
}

// nosecDirective reports whether the text after #nosec has the shape of a
// directive. Prose that mentions the marker ("#nosec annotations are counted")
// is not evidence of an annotation, and a Go string literal that contains the
// marker is not a comment at all.
func nosecDirective(tail string) bool {
	tail = strings.TrimLeft(tail, " \t")
	if tail == "" {
		return true
	}
	if strings.HasPrefix(tail, "—") || strings.HasPrefix(tail, "--") {
		return true
	}
	loc := nosecCodePattern.FindStringIndex(tail)
	return loc != nil && loc[0] == 0
}

// scanNosec counts #nosec annotations that lack either a rule code or a
// justification. The key is "file|CODE" so a new unjustified annotation in an
// already-annotated file is still detected.
func scanNosec(repoDir string) (map[string]int, error) {
	counts := make(map[string]int)
	err := filepath.WalkDir(repoDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "research":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G122,G304 — the walk is rooted at the repository directory and reads only .go files
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, data, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		for _, group := range file.Comments {
			for _, comment := range group.List {
				for line := range strings.SplitSeq(comment.Text, "\n") {
					_, after, ok := strings.Cut(line, "#nosec")
					if !ok {
						continue
					}
					tail := after
					if !nosecDirective(tail) {
						continue
					}
					codes := nosecCodePattern.FindAllString(tail, -1)
					justified := false
					for _, sep := range []string{"—", "--"} {
						if _, after, ok := strings.Cut(tail, sep); ok {
							if len(strings.TrimSpace(after)) >= 3 {
								justified = true
							}
						}
					}
					if len(codes) == 0 || !justified {
						rule := "none"
						if len(codes) > 0 {
							sort.Strings(codes)
							rule = strings.Join(codes, ",")
						}
						counts[rel+"|"+rule]++
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan #nosec: %w", err)
	}
	return counts, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func totalCount(m map[string]int) int {
	total := 0
	for _, n := range m {
		total += n
	}
	return total
}

// writef reports to a diagnostic or report writer. A failure to write
// diagnostics cannot itself be reported, so the write ends without changing
// the tool's exit code.
func writef(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return
	}
}

func writeln(w io.Writer, args ...any) {
	if _, err := fmt.Fprintln(w, args...); err != nil {
		return
	}
}

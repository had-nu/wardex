// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command check-boundaries verifies that the repository's import graph follows
// the module map in doc/architecture/modules.yaml.
//
// What it prevents: a package reaching across a module boundary that the
// manifest says it does not depend on. The compiler cannot see that boundary
// while the code still lives in one Go module, so the guard derives it from the
// import graph. When a module moves behind its own facade, the same manifest
// keeps checking the contracts between modules.
//
// Current violations are recorded in the legacy section. -init regenerates that
// section from the graph, so the baseline cannot be written by hand into
// something wider than the truth. A new edge fails, and an edge that disappears
// without its baseline entry being removed also fails.
//
// Usage:
//
//	go run ./tools/check-boundaries
//	go run ./tools/check-boundaries -tags grpc
//	go run ./tools/check-boundaries -init
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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const manifestVersion = 1

// moduleSpec is one architectural module.
type moduleSpec struct {
	Packages  []string `yaml:"packages"`
	MayImport []string `yaml:"may_import"`
}

// legacyEntry is either the destination of a package that has not moved yet,
// or a baseline exemption for an edge that violates the manifest today.
type legacyEntry struct {
	Package string   `yaml:"package"`
	Target  string   `yaml:"target"`
	Allow   []string `yaml:"allow"`
}

// manifest is doc/architecture/modules.yaml.
type manifest struct {
	Version int                   `yaml:"version"`
	Modules map[string]moduleSpec `yaml:"modules"`
	Legacy  []legacyEntry         `yaml:"legacy"`
}

// pkgInfo is one package in the scanned graph. Imports maps a repository
// package to the first file:line that imports it.
type pkgInfo struct {
	Path    string
	Imports map[string]string
}

type graph map[string]*pkgInfo

// goListPkg is the subset of `go list -json` this tool reads.
type goListPkg struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Module     *struct {
		Path string
		Main bool
	}
}

// finding is one edge that breaks a rule.
type finding struct {
	From    string
	To      string
	Rule    string
	Pos     string
	Message string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-boundaries", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "doc/architecture/modules.yaml", "path to the module manifest")
	repoDir := fs.String("repo", ".", "repository root")
	tags := fs.String("tags", "", "build tags passed to go list")
	initFlag := fs.Bool("init", false, "regenerate the legacy baseline from the current graph")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	m, err := loadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "check-boundaries: %v\n", err)
		return 2
	}

	var g graph
	if *initFlag {
		// The baseline must hold for every build configuration the CI checks.
		// Default and grpc are merged so -init cannot produce a baseline that
		// only passes without the tag.
		plain, err := scanGraph(*repoDir, "")
		if err != nil {
			fmt.Fprintf(stderr, "check-boundaries: %v\n", err)
			return 2
		}
		grpc, err := scanGraph(*repoDir, "grpc")
		if err != nil {
			fmt.Fprintf(stderr, "check-boundaries: %v\n", err)
			return 2
		}
		g = mergeGraphs(plain, grpc)
	} else {
		g, err = scanGraph(*repoDir, *tags)
		if err != nil {
			fmt.Fprintf(stderr, "check-boundaries: %v\n", err)
			return 2
		}
	}

	e, err := newEngine(m, g)
	if err != nil {
		fmt.Fprintf(stderr, "check-boundaries: %v\n", err)
		return 2
	}

	if *initFlag {
		if len(e.unclassified) > 0 {
			for _, p := range e.unclassified {
				fmt.Fprintf(stderr, "check-boundaries: R6 %s has no destination; add {package: %s, target: <module>} to legacy\n", p, p)
			}
			return 3
		}
		e.computeFindings()
		m.Legacy = e.initLegacy()
		if err := writeManifest(*manifestPath, m); err != nil {
			fmt.Fprintf(stderr, "check-boundaries: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "check-boundaries: wrote %s (%d packages, %d legacy entries)\n", *manifestPath, len(g), len(m.Legacy))
		return 0
	}

	if len(e.unclassified) > 0 {
		for _, p := range e.unclassified {
			rule := unclassifiedRule(p)
			fmt.Fprintf(stdout, "%s %s: package has no module and no legacy destination\n", rule, p)
		}
		fmt.Fprintf(stderr, "check-boundaries: %d unclassified package(s)\n", len(e.unclassified))
		return 3
	}

	e.computeFindings()
	newFindings, stale := e.compareBaseline()

	sortFindings(newFindings)
	for _, f := range newFindings {
		pos := f.Pos
		if pos == "" {
			pos = f.From
		}
		fmt.Fprintf(stdout, "%s %s %s -> %s: %s\n", pos, f.Rule, f.From, f.To, f.Message)
	}
	sort.Strings(stale)
	for _, s := range stale {
		fmt.Fprintf(stdout, "baseline: %s\n", s)
	}

	if len(newFindings) > 0 {
		fmt.Fprintf(stderr, "check-boundaries: %d new boundary violation(s); %d baseline entr(ies)\n", len(newFindings), len(m.Legacy))
		return 1
	}
	if len(stale) > 0 {
		fmt.Fprintf(stderr, "check-boundaries: stale baseline; run 'go run ./tools/check-boundaries -init'\n")
		return 2
	}

	fmt.Fprintf(stdout, "check-boundaries: %d packages, %d modules, %d baseline entries, 0 new violations\n", len(g), len(m.Modules), len(m.Legacy))
	return 0
}

// loadManifest reads and validates the manifest. It fails on a malformed or
// self-inconsistent file, never on a boundary violation.
func loadManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Version != manifestVersion {
		return nil, fmt.Errorf("manifest version %d is not %d", m.Version, manifestVersion)
	}
	if len(m.Modules) == 0 {
		return nil, errors.New("manifest has no modules")
	}

	for name, mod := range m.Modules {
		if name == "" {
			return nil, errors.New("manifest has a module with an empty name")
		}
		if len(mod.Packages) == 0 {
			return nil, fmt.Errorf("module %q has no packages", name)
		}
		for i, p := range mod.Packages {
			norm, err := normalisePath(p)
			if err != nil {
				return nil, fmt.Errorf("module %q package %q: %w", name, p, err)
			}
			mod.Packages[i] = norm
		}
		for _, dep := range mod.MayImport {
			if _, ok := m.Modules[dep]; !ok {
				return nil, fmt.Errorf("module %q may_import unknown module %q", name, dep)
			}
		}
		m.Modules[name] = mod
	}
	if err := checkPrefixes(m.Modules); err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(m.Legacy))
	for i, entry := range m.Legacy {
		pkg, err := normalisePath(entry.Package)
		if err != nil {
			return nil, fmt.Errorf("legacy package %q: %w", entry.Package, err)
		}
		if seen[pkg] {
			return nil, fmt.Errorf("legacy lists %q twice", pkg)
		}
		seen[pkg] = true
		if _, ok := m.Modules[entry.Target]; !ok {
			return nil, fmt.Errorf("legacy package %q targets unknown module %q", pkg, entry.Target)
		}
		allow := make([]string, 0, len(entry.Allow))
		for _, a := range entry.Allow {
			norm, err := normalisePath(a)
			if err != nil {
				return nil, fmt.Errorf("legacy package %q allow %q: %w", pkg, a, err)
			}
			allow = append(allow, norm)
		}
		sort.Strings(allow)
		m.Legacy[i] = legacyEntry{Package: pkg, Target: entry.Target, Allow: allow}
	}
	return &m, nil
}

// checkPrefixes rejects two modules that claim the same package space. Without
// this, a package could silently change module when a new prefix is added.
func checkPrefixes(modules map[string]moduleSpec) error {
	type claim struct {
		module string
		prefix string
	}
	var claims []claim
	for name, mod := range modules {
		for _, p := range mod.Packages {
			claims = append(claims, claim{module: name, prefix: p})
		}
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].prefix == claims[j].prefix {
			return claims[i].module < claims[j].module
		}
		return claims[i].prefix < claims[j].prefix
	})
	for i := 0; i < len(claims); i++ {
		for j := i + 1; j < len(claims); j++ {
			a, b := claims[i], claims[j]
			if a.module == b.module {
				continue
			}
			if within(a.prefix, b.prefix) || within(b.prefix, a.prefix) {
				return fmt.Errorf("module %q package %q overlaps module %q package %q", a.module, a.prefix, b.module, b.prefix)
			}
		}
	}
	return nil
}

// normalisePath turns a manifest or go list path into a repository-relative
// package path. The root package is ".".
func normalisePath(p string) (string, error) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		p = "."
	}
	if p == "." {
		return p, nil
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "../") || p == ".." {
		return "", fmt.Errorf("%q is not repository-relative", p)
	}
	return p, nil
}

// within reports whether pkg is prefix itself or below it. Prefixes are
// directory-like: "pkg/gate" does not contain "pkg/gateway".
func within(pkg, prefix string) bool {
	if prefix == "." {
		return pkg == "."
	}
	return pkg == prefix || strings.HasPrefix(pkg, prefix+"/")
}

// scanGraph runs go list from repoDir and parses imports from the files that
// the build configuration selects. Test files are not in GoFiles, so their
// imports never enter the graph.
func scanGraph(repoDir, tags string) (graph, error) {
	args := []string{"list", "-json"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "./...")

	var stdout, stderr bytes.Buffer
	// #nosec G204 -- the subcommand and flags are literals; repoDir and tags
	// come from the caller of a local development tool, not from user input in
	// a network service.
	cmd := exec.Command("go", args...)
	cmd.Dir = repoDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	dec := json.NewDecoder(&stdout)
	var listed []goListPkg
	for {
		var p goListPkg
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list: %w", err)
		}
		listed = append(listed, p)
	}

	modulePath := ""
	for _, p := range listed {
		if p.Module != nil && p.Module.Main {
			modulePath = p.Module.Path
			break
		}
	}
	if modulePath == "" {
		return nil, errors.New("go list found no package in the main module")
	}

	g := make(graph, len(listed))
	for _, p := range listed {
		if !isRepoImport(modulePath, p.ImportPath) {
			continue
		}
		rel := strings.TrimPrefix(p.ImportPath, modulePath+"/")
		if rel == p.ImportPath {
			rel = "."
		}
		info := &pkgInfo{Path: rel, Imports: make(map[string]string)}
		files := append(append([]string{}, p.GoFiles...), p.CgoFiles...)
		sort.Strings(files)
		for _, name := range files {
			full := filepath.Join(p.Dir, name)
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, full, nil, parser.ImportsOnly)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", full, err)
			}
			for _, imp := range file.Imports {
				target, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					continue
				}
				if !isRepoImport(modulePath, target) {
					continue
				}
				targetRel := strings.TrimPrefix(target, modulePath+"/")
				if targetRel == target {
					targetRel = "."
				}
				if targetRel == rel {
					continue
				}
				if _, seen := info.Imports[targetRel]; seen {
					continue
				}
				pos := fset.Position(imp.Pos())
				fileRel, relErr := filepath.Rel(repoDir, pos.Filename)
				if relErr != nil {
					fileRel = pos.Filename
				}
				info.Imports[targetRel] = fmt.Sprintf("%s:%d", filepath.ToSlash(fileRel), pos.Line)
			}
		}
		g[rel] = info
	}
	return g, nil
}

func isRepoImport(modulePath, importPath string) bool {
	return importPath == modulePath || strings.HasPrefix(importPath, modulePath+"/")
}

// mergeGraphs unions two build configurations.
func mergeGraphs(graphs ...graph) graph {
	out := make(graph)
	for _, g := range graphs {
		for path, info := range g {
			if out[path] == nil {
				out[path] = &pkgInfo{Path: path, Imports: make(map[string]string)}
			}
			for target, pos := range info.Imports {
				if _, seen := out[path].Imports[target]; !seen {
					out[path].Imports[target] = pos
				}
			}
		}
	}
	return out
}

// engine classifies the graph and applies the rules.
type engine struct {
	m            *manifest
	g            graph
	moduleOf     map[string]string
	legacyOf     map[string]*legacyEntry
	effective    map[string]string
	unclassified []string
	findings     map[string]map[string]finding
}

func newEngine(m *manifest, g graph) (*engine, error) {
	e := &engine{
		m:         m,
		g:         g,
		moduleOf:  make(map[string]string, len(g)),
		legacyOf:  make(map[string]*legacyEntry, len(m.Legacy)),
		effective: make(map[string]string, len(g)),
		findings:  make(map[string]map[string]finding),
	}
	for i := range m.Legacy {
		entry := &m.Legacy[i]
		e.legacyOf[entry.Package] = entry
	}

	paths := make([]string, 0, len(g))
	for p := range g {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, pkg := range paths {
		var matched string
		for name, mod := range m.Modules {
			for _, prefix := range mod.Packages {
				if within(pkg, prefix) {
					if matched != "" && matched != name {
						return nil, fmt.Errorf("package %q matches modules %q and %q", pkg, matched, name)
					}
					matched = name
				}
			}
		}
		if matched != "" {
			e.moduleOf[pkg] = matched
		}

		entry := e.legacyOf[pkg]
		switch {
		case matched != "" && entry != nil:
			if entry.Target != matched {
				return nil, fmt.Errorf("legacy package %q targets %q but the module map classifies it as %q", pkg, entry.Target, matched)
			}
			e.effective[pkg] = matched
		case matched != "":
			e.effective[pkg] = matched
		case entry != nil:
			e.effective[pkg] = entry.Target
		default:
			e.unclassified = append(e.unclassified, pkg)
		}
	}
	return e, nil
}

// computeFindings walks every edge and records one reason per violating edge.
func (e *engine) computeFindings() {
	e.findings = make(map[string]map[string]finding)
	for _, from := range sortedGraphKeys(e.g) {
		info := e.g[from]
		fromModule := e.effective[from]

		// A package that imports more than one foreign module is a second
		// violation, independent of whether each individual edge is allowed by
		// may_import. Only the facade aggregates modules. An edge that R2
		// already rejects is not counted here: the violation is the direct
		// import, not the aggregation.
		foreign := make(map[string]bool)
		for to := range info.Imports {
			toModule := e.effective[to]
			if toModule == "" || toModule == fromModule || toModule == "contracts" || toModule == "kit" {
				continue
			}
			if e.allowedModules(fromModule)[toModule] {
				foreign[toModule] = true
			}
		}

		for to := range info.Imports {
			toModule := e.effective[to]
			if toModule == "" {
				e.addFinding(from, to, "R6", info.Imports[to], fmt.Sprintf("imports %s, which has no module and no legacy destination", to))
				continue
			}
			if rule, message := e.edgeRule(from, to, fromModule, toModule); rule != "" {
				e.addFinding(from, to, rule, info.Imports[to], message)
				continue
			}
			if len(foreign) > 1 && fromModule != "facade" && foreign[toModule] {
				e.addFinding(from, to, "R3", info.Imports[to], fmt.Sprintf("module %q imports %d foreign modules; only the facade may aggregate modules", fromModule, len(foreign)))
			}
		}
	}
}

func (e *engine) edgeRule(from, to, fromModule, toModule string) (string, string) {
	switch fromModule {
	case "contracts":
		return "R1", fmt.Sprintf("contracts must not import repository package %s", to)
	case "kit":
		if toModule != "contracts" && toModule != "kit" {
			return "R1", fmt.Sprintf("kit may import only contracts and kit, not %s (module %s)", to, toModule)
		}
	case "tools":
		return "R8", fmt.Sprintf("tools is a leaf and must not import %s (module %s)", to, toModule)
	}
	if isUIPath(to) && fromModule != "adapters" {
		return "R4", fmt.Sprintf("only adapters may import %s (from module %s)", to, fromModule)
	}
	if fromModule == "adapters" && isInternalPath(to) {
		return "R5", fmt.Sprintf("adapters may use only public module APIs, not %s", to)
	}
	if !e.allowedModules(fromModule)[toModule] {
		return "R2", fmt.Sprintf("module %q may not import %s (module %q); allowed: %s", fromModule, to, toModule, strings.Join(e.allowedList(fromModule), ", "))
	}
	return "", ""
}

func (e *engine) allowedModules(module string) map[string]bool {
	allowed := map[string]bool{module: true}
	switch module {
	case "contracts":
		return allowed
	case "kit":
		allowed["contracts"] = true
		return allowed
	case "tools":
		return allowed
	case "tests", "adapters":
		allowed["facade"] = true
		allowed["contracts"] = true
		allowed["kit"] = true
		return allowed
	}
	mod, ok := e.m.Modules[module]
	if !ok {
		return allowed
	}
	allowed["contracts"] = true
	allowed["kit"] = true
	for _, dep := range mod.MayImport {
		allowed[dep] = true
	}
	return allowed
}

func (e *engine) allowedList(module string) []string {
	allowed := e.allowedModules(module)
	out := make([]string, 0, len(allowed))
	for name := range allowed {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (e *engine) addFinding(from, to, rule, pos, message string) {
	if e.findings[from] == nil {
		e.findings[from] = make(map[string]finding)
	}
	if _, exists := e.findings[from][to]; exists {
		return
	}
	e.findings[from][to] = finding{From: from, To: to, Rule: rule, Pos: pos, Message: message}
}

// compareBaseline returns the edges that are not allowed and the baseline
// entries that no longer describe a violation.
func (e *engine) compareBaseline() ([]finding, []string) {
	var newFindings []finding
	var stale []string

	allowByPackage := make(map[string][]string, len(e.m.Legacy))
	for _, entry := range e.m.Legacy {
		allowByPackage[entry.Package] = entry.Allow
		if _, ok := e.g[entry.Package]; !ok {
			stale = append(stale, fmt.Sprintf("%s is listed in legacy but no longer exists", entry.Package))
		}
	}

	for from, targets := range e.findings {
		allowed := allowByPackage[from]
		for to, f := range targets {
			if !allowMatches(allowed, to) {
				newFindings = append(newFindings, f)
			}
		}
	}

	for _, entry := range e.m.Legacy {
		if e.moduleOf[entry.Package] != "" && len(entry.Allow) == 0 {
			stale = append(stale, fmt.Sprintf("%s is in module %q and has no baseline edges; remove the entry", entry.Package, e.moduleOf[entry.Package]))
			continue
		}
		for _, allowed := range entry.Allow {
			matched := false
			for to := range e.findings[entry.Package] {
				if allowMatches([]string{allowed}, to) {
					matched = true
					break
				}
			}
			if !matched {
				stale = append(stale, fmt.Sprintf("%s allows %s, but that is not a current violation", entry.Package, allowed))
			}
		}
	}
	return newFindings, stale
}

func allowMatches(allowed []string, target string) bool {
	for _, a := range allowed {
		if within(target, a) {
			return true
		}
	}
	return false
}

// initLegacy builds the baseline from the current findings. Unclassified
// packages keep their destination even when they have no violating imports;
// module packages get an entry only while they have violations.
func (e *engine) initLegacy() []legacyEntry {
	allowByPackage := make(map[string]map[string]bool)
	for from, targets := range e.findings {
		if allowByPackage[from] == nil {
			allowByPackage[from] = make(map[string]bool)
		}
		for to := range targets {
			allowByPackage[from][to] = true
		}
	}

	entries := make(map[string]legacyEntry)
	for _, old := range e.m.Legacy {
		if e.moduleOf[old.Package] == "" {
			entries[old.Package] = legacyEntry{Package: old.Package, Target: old.Target}
		}
	}
	for pkg := range e.g {
		module := e.moduleOf[pkg]
		targets := allowByPackage[pkg]
		if module == "" {
			entry := entries[pkg]
			entry.Package = pkg
			entry.Allow = sortedSet(targets)
			entries[pkg] = entry
			continue
		}
		if len(targets) == 0 {
			delete(entries, pkg)
			continue
		}
		entries[pkg] = legacyEntry{Package: pkg, Target: module, Allow: sortedSet(targets)}
	}

	out := make([]legacyEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

func writeManifest(path string, m *manifest) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	header := "# Generated by: go run ./tools/check-boundaries -init\n" +
		"# The legacy section records current boundary violations. A new edge must\n" +
		"# be fixed or listed here with the module it is migrating to; an entry that\n" +
		"# no longer matches the graph is an error. Edit modules by hand; regenerate\n" +
		"# legacy with -init after a migration.\n"
	if err := os.WriteFile(path, append([]byte(header), data...), 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func sortedGraphKeys(g graph) []string {
	keys := make([]string, 0, len(g))
	for k := range g {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortFindings(findings []finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].From != findings[j].From {
			return findings[i].From < findings[j].From
		}
		return findings[i].To < findings[j].To
	})
}

func isUIPath(pkg string) bool {
	return pkg == "pkg/ui" || strings.HasPrefix(pkg, "pkg/ui/")
}

// unclassifiedRule names the rule that requires a destination. R7 calls out
// production code outside pkg/, which must move into a module rather than stay
// in an unclassified corner of the repository.
func unclassifiedRule(pkg string) string {
	if !strings.HasPrefix(pkg, "pkg/") {
		return "R7"
	}
	return "R6"
}

func isInternalPath(pkg string) bool {
	return pkg == "internal" || strings.HasPrefix(pkg, "internal/") || strings.Contains(pkg, "/internal/")
}

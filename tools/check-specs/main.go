// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command check-specs verifies that the active specifications follow the
// canonical structure and vocabulary defined in SPEC-M0-baseline.md, section
// 5.6.
//
// The checks are structural on purpose. The tool does not judge whether a
// decision is correct; it only verifies that the document can be found, named,
// read and cross-referenced in the same way as every other specification.
//
// Usage:
//
//	go run ./tools/check-specs
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// canonicalTitles is the fixed sequence of top-level sections.
var canonicalTitles = []string{
	"Purpose",
	"Scope",
	"Inherited decisions",
	"Prerequisites",
	"Components",
	"Error model",
	"Standalone use",
	"Test plan",
	"Migration plan",
	"Definition of done",
	"Risks",
	"Not verified",
}

// cardRows is the fixed set of rows in the module card at the start of section 5.
var cardRows = []string{
	"Inputs",
	"Outputs",
	"Public API",
	"Allowed dependencies",
	"Absorbed packages",
	"Absorbed commands",
	"Branch",
	"Estimate",
}

var (
	specNamePattern  = regexp.MustCompile(`^SPEC-(M[0-9]+|X)-[a-z0-9][a-z0-9-]*\.md$`)
	headingPattern   = regexp.MustCompile(`^##\s+([0-9]+)\.\s+(.+?)\s*$`)
	componentPattern = regexp.MustCompile(`^###\s+([0-9]+\.[0-9]+)\s+`)
	idTablePattern   = regexp.MustCompile(`^\|\s*(D[0-9]+|M[0-9]+-D[0-9]+|G[0-9]+|M[0-9]+-P[0-9]+(?:\.[0-9]+)?|R[0-9]+)\s*\|`)
	idBulletPattern  = regexp.MustCompile(`^-\s+(?:\*\*)?(D[0-9]+|M[0-9]+-D[0-9]+|G[0-9]+|M[0-9]+-P[0-9]+(?:\.[0-9]+)?|R[0-9]+)\b`)
	xrefPattern      = regexp.MustCompile(`\bM[0-9]+#[A-Za-z0-9][A-Za-z0-9.-]*\b`)
	inlineCode       = regexp.MustCompile("`[^`]*`")
)

type manifest struct {
	Version  int         `yaml:"version"`
	Language string      `yaml:"language"`
	Specs    []specEntry `yaml:"specs"`
}

type specEntry struct {
	File         string `yaml:"file"`
	ID           string `yaml:"id"`
	Title        string `yaml:"title"`
	Status       string `yaml:"status"`
	Owner        string `yaml:"owner"`
	Base         string `yaml:"base"`
	FrozenAt     string `yaml:"frozen_at"`
	SupersededBy string `yaml:"superseded_by"`
	Abstract     string `yaml:"abstract"`
}

type glossary struct {
	Version   int      `yaml:"version"`
	Language  string   `yaml:"language"`
	Reserved  []string `yaml:"reserved"`
	Terms     []term   `yaml:"terms"`
	Forbidden []string `yaml:"forbidden"`
}

type term struct {
	Term                 string   `yaml:"term"`
	Definition           string   `yaml:"definition"`
	Note                 string   `yaml:"note"`
	Reserved             bool     `yaml:"reserved"`
	Avoid                []string `yaml:"avoid"`
	AllowFirstDefinition bool     `yaml:"allow_first_definition"`
	AllowIn              []string `yaml:"allow_in"`
	Exempt               []string `yaml:"exempt"`
}

// violation is one failed structural check. Line is 1-based and zero when the
// violation applies to the whole document.
type violation struct {
	File    string
	Line    int
	Rule    string
	Message string
}

func (v violation) String() string {
	if v.Line > 0 {
		return fmt.Sprintf("%s:%d %s %s", v.File, v.Line, v.Rule, v.Message)
	}
	return fmt.Sprintf("%s %s %s", v.File, v.Rule, v.Message)
}

type report struct {
	Violations   []violation
	Unclassified []violation
	Checked      int
}

func main() {
	root := flag.String("root", ".", "repository root to check")
	manifestPath := flag.String("manifest", "doc/specs/specs.yaml", "spec inventory, relative to the root")
	glossaryPath := flag.String("glossary", "doc/specs/glossary.yaml", "glossary, relative to the root")
	flag.Parse()

	rep, err := check(*root, *manifestPath, *glossaryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-specs: %v\n", err)
		os.Exit(2)
	}

	for _, v := range rep.Violations {
		fmt.Println(v)
	}
	for _, v := range rep.Unclassified {
		fmt.Println(v)
	}
	if len(rep.Violations) > 0 || len(rep.Unclassified) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d violation(s), %d unclassified item(s)\n", len(rep.Violations), len(rep.Unclassified))
		if len(rep.Unclassified) > 0 {
			os.Exit(3)
		}
		os.Exit(1)
	}

	fmt.Printf("checked %d spec(s)\n", rep.Checked)
}

// check reads the inventory and glossary and validates every active spec and
// the template. Legacy specs are checked only for their manifest entry and
// abstract, because their content is frozen in Portuguese.
func check(root, manifestPath, glossaryPath string) (report, error) {
	var rep report

	man, err := readManifest(filepath.Join(root, manifestPath))
	if err != nil {
		return rep, err
	}
	gl, err := readGlossary(filepath.Join(root, glossaryPath))
	if err != nil {
		return rep, err
	}
	if err := validateManifest(man); err != nil {
		return rep, err
	}
	if err := validateGlossary(gl); err != nil {
		return rep, err
	}

	specsDir := filepath.Join(root, "doc", "specs")
	files := make(map[string]specEntry, len(man.Specs))
	ids := make(map[string]specEntry, len(man.Specs))
	for _, entry := range man.Specs {
		if _, exists := files[entry.File]; exists {
			return rep, fmt.Errorf("manifest: duplicate file %q", entry.File)
		}
		if _, exists := ids[entry.ID]; exists {
			return rep, fmt.Errorf("manifest: duplicate id %q", entry.ID)
		}
		files[entry.File] = entry
		ids[entry.ID] = entry
	}

	type loaded struct {
		entry specEntry
		body  string
		lines []string
	}
	var active []loaded

	for _, entry := range man.Specs {
		if filepath.IsAbs(entry.File) || strings.Contains(entry.File, "..") {
			return rep, fmt.Errorf("manifest: %q must be a relative path inside doc/specs", entry.File)
		}
		path := filepath.Join(specsDir, filepath.FromSlash(entry.File))
		info, statErr := os.Stat(path)
		if statErr != nil {
			return rep, fmt.Errorf("manifest: %s: %w", entry.File, statErr)
		}
		if info.IsDir() {
			return rep, fmt.Errorf("manifest: %s is a directory", entry.File)
		}

		switch entry.Status {
		case "legacy-pt":
			display := filepath.ToSlash(filepath.Join("doc/specs", entry.File))
			if strings.TrimSpace(entry.Abstract) == "" {
				rep.Violations = append(rep.Violations, violation{
					File: display, Rule: "SPEC-ABSTRACT",
					Message: "legacy-pt spec needs an English abstract",
				})
			}
			if entry.SupersededBy != "" {
				target, exists := files[entry.SupersededBy]
				if !exists || target.Status != "active" {
					rep.Violations = append(rep.Violations, violation{
						File: display, Rule: "SPEC-SUPERSEDED",
						Message: fmt.Sprintf("superseded_by %q is not an active spec", entry.SupersededBy),
					})
				}
			}
		case "active":
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return rep, fmt.Errorf("read %s: %w", entry.File, readErr)
			}
			active = append(active, loaded{entry: entry, body: string(body), lines: strings.Split(string(body), "\n")})
		}
	}

	// Collect the IDs first so that a cross-reference can point at another spec.
	known := make(map[string]map[string]bool, len(active))
	for _, spec := range active {
		set := make(map[string]bool)
		for id := range collectIDs(spec.lines) {
			set[id] = true
		}
		known[spec.entry.ID] = set
	}

	for _, spec := range active {
		rep.Checked++
		rep.Violations = append(rep.Violations, checkSpec(spec.entry.File, spec.lines, gl, known, false)...)
	}

	templatePath := filepath.Join(specsDir, "TEMPLATE_module.md")
	if body, readErr := os.ReadFile(templatePath); readErr == nil {
		rep.Checked++
		rep.Violations = append(rep.Violations, checkSpec("TEMPLATE_module.md", strings.Split(string(body), "\n"), gl, known, true)...)
	} else if os.IsNotExist(readErr) {
		rep.Violations = append(rep.Violations, violation{
			File: "doc/specs/TEMPLATE_module.md", Rule: "SPEC-TEMPLATE",
			Message: "missing spec template",
		})
	} else {
		return rep, fmt.Errorf("read template: %w", readErr)
	}

	err = filepath.WalkDir(specsDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		rel, relErr := filepath.Rel(specsDir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "TEMPLATE_module.md" {
			return nil
		}
		if _, exists := files[rel]; !exists {
			rep.Unclassified = append(rep.Unclassified, violation{
				File: filepath.ToSlash(filepath.Join("doc/specs", rel)), Rule: "SPEC-INVENTORY",
				Message: "spec is not listed in doc/specs/specs.yaml",
			})
		}
		return nil
	})
	if err != nil {
		return rep, err
	}

	return rep, nil
}

func readManifest(path string) (manifest, error) {
	var m manifest
	body, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := yaml.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func readGlossary(path string) (glossary, error) {
	var g glossary
	body, err := os.ReadFile(path)
	if err != nil {
		return g, err
	}
	if err := yaml.Unmarshal(body, &g); err != nil {
		return g, fmt.Errorf("%s: %w", path, err)
	}
	return g, nil
}

func validateManifest(m manifest) error {
	if m.Version != 1 {
		return fmt.Errorf("manifest: version = %d, want 1", m.Version)
	}
	if m.Language != "en-GB" {
		return fmt.Errorf("manifest: language = %q, want en-GB", m.Language)
	}
	if len(m.Specs) == 0 {
		return fmt.Errorf("manifest: no specs")
	}
	for _, entry := range m.Specs {
		if strings.TrimSpace(entry.File) == "" || strings.TrimSpace(entry.ID) == "" {
			return fmt.Errorf("manifest: an entry has an empty file or id")
		}
		switch entry.Status {
		case "active", "legacy-pt":
		default:
			return fmt.Errorf("manifest: %s: status = %q, want active or legacy-pt", entry.File, entry.Status)
		}
		if entry.Status == "active" && (strings.TrimSpace(entry.Owner) == "" || strings.TrimSpace(entry.Base) == "") {
			return fmt.Errorf("manifest: %s: active spec needs owner and base", entry.File)
		}
	}
	return nil
}

func validateGlossary(g glossary) error {
	if g.Version != 1 {
		return fmt.Errorf("glossary: version = %d, want 1", g.Version)
	}
	if g.Language != "en-GB" {
		return fmt.Errorf("glossary: language = %q, want en-GB", g.Language)
	}
	if len(g.Forbidden) == 0 {
		return fmt.Errorf("glossary: no forbidden terms")
	}
	for _, forbidden := range g.Forbidden {
		if strings.TrimSpace(forbidden) == "" {
			return fmt.Errorf("glossary: an empty forbidden term")
		}
	}
	seen := make(map[string]bool, len(g.Terms))
	for _, t := range g.Terms {
		if strings.TrimSpace(t.Term) == "" || strings.TrimSpace(t.Definition) == "" {
			return fmt.Errorf("glossary: term %q has no definition", t.Term)
		}
		if seen[t.Term] {
			return fmt.Errorf("glossary: duplicate term %q", t.Term)
		}
		seen[t.Term] = true
	}
	if !seen["package"] {
		return fmt.Errorf("glossary: reserved Go term %q is not defined", "package")
	}
	reserved := make(map[string]bool, len(g.Reserved))
	for _, r := range g.Reserved {
		reserved[r] = true
	}
	if !reserved["package"] {
		return fmt.Errorf("glossary: %q must be in the reserved list", "package")
	}
	return nil
}

// checkSpec validates one Markdown document. When template is true the file
// name rule is skipped, because the template is not a real spec.
func checkSpec(name string, lines []string, g glossary, known map[string]map[string]bool, template bool) []violation {
	var out []violation
	display := filepath.ToSlash(filepath.Join("doc/specs", name))
	add := func(line int, rule, message string) {
		out = append(out, violation{File: display, Line: line, Rule: rule, Message: message})
	}

	if !template && !specNamePattern.MatchString(name) {
		add(0, "SPEC-NAME", "file name must match SPEC-M<n>-<id>.md or SPEC-X-<topic>.md")
	}

	titleLine := firstLineWithPrefix(lines, "# ")
	if titleLine == 0 {
		add(0, "SPEC-TITLE", "missing level-1 title")
	} else {
		title := strings.TrimSpace(strings.TrimPrefix(lines[titleLine-1], "# "))
		if !strings.HasPrefix(title, "SPEC-") || !strings.Contains(title, " — ") {
			add(titleLine, "SPEC-TITLE", "title must have the form SPEC-... — ...")
		}
	}

	if bylineLine(lines) == 0 {
		add(0, "SPEC-BYLINE", "missing byline (Wardex · ... · base: ...)")
	}

	headings := collectHeadings(lines)
	if len(headings) != len(canonicalTitles) {
		add(0, "SPEC-SECTION", fmt.Sprintf("found %d top-level sections, want %d", len(headings), len(canonicalTitles)))
	}
	for i, want := range canonicalTitles {
		if i >= len(headings) {
			break
		}
		got := headings[i]
		if got.Number != i+1 || got.Title != want {
			add(got.Line, "SPEC-SECTION", fmt.Sprintf("section %d is %q, want %q", got.Number, got.Title, want))
		}
	}

	start, end := sectionBounds(lines, 5)
	for _, row := range cardRows {
		if !hasTableRow(lines, start, end, row) {
			add(0, "SPEC-CARD", fmt.Sprintf("module card is missing row %q", row))
		}
	}

	out = append(out, checkIDs(display, lines, known)...)
	out = append(out, checkLanguage(display, lines, g)...)
	return out
}

type heading struct {
	Number int
	Title  string
	Line   int
}

func collectHeadings(lines []string) []heading {
	var out []heading
	inFence := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		m := headingPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		number, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		out = append(out, heading{Number: number, Title: m[2], Line: i + 1})
	}
	return out
}

func sectionBounds(lines []string, number int) (start, end int) {
	headings := collectHeadings(lines)
	for i, h := range headings {
		if h.Number != number {
			continue
		}
		start = h.Line - 1
		if i+1 < len(headings) {
			end = headings[i+1].Line - 1
		} else {
			end = len(lines)
		}
		return start, end
	}
	return -1, -1
}

func hasTableRow(lines []string, start, end int, row string) bool {
	if start < 0 || end < 0 || start >= end {
		return false
	}
	pattern := regexp.MustCompile(`^\|\s*` + regexp.QuoteMeta(row) + `\s*\|`)
	return slices.ContainsFunc(lines[start:end], pattern.MatchString)
}

func firstLineWithPrefix(lines []string, prefix string) int {
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return i + 1
		}
	}
	return 0
}

func bylineLine(lines []string) int {
	limit := min(len(lines), 12)
	for i := range limit {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "Wardex · ") && strings.Contains(line, "base:") {
			return i + 1
		}
	}
	return 0
}

// collectIDs returns the definitions in the document. A definition is an ID in
// the first cell of a table row, an ID at the start of a bullet, or a numbered
// component heading such as 5.2.
func collectIDs(lines []string) map[string]int {
	defs := make(map[string]int)
	headings := collectHeadings(lines)
	for i, line := range lines {
		if m := idTablePattern.FindStringSubmatch(line); m != nil {
			defs[m[1]] = i + 1
		}
		if canDefineInBullet(sectionAt(headings, i+1)) {
			if m := idBulletPattern.FindStringSubmatch(line); m != nil {
				defs[m[1]] = i + 1
			}
		}
		if m := componentPattern.FindStringSubmatch(line); m != nil {
			defs[m[1]] = i + 1
		}
	}
	return defs
}

// canDefineInBullet limits bullet definitions to the sections that own them:
// prerequisites and steps (4 and 9) and components (5). A bullet in the risk or
// "not verified" section that starts with an ID is a reference, not a definition.
func canDefineInBullet(section int) bool {
	return section == 4 || section == 5 || section == 9
}

func sectionAt(headings []heading, line int) int {
	current := 0
	for _, h := range headings {
		if h.Line > line {
			break
		}
		current = h.Number
	}
	return current
}

func checkIDs(display string, lines []string, known map[string]map[string]bool) []violation {
	var out []violation
	defs := make(map[string]int)
	headings := collectHeadings(lines)
	for i, line := range lines {
		var id string
		if m := idTablePattern.FindStringSubmatch(line); m != nil {
			id = m[1]
		} else if m := componentPattern.FindStringSubmatch(line); m != nil {
			id = m[1]
		} else if canDefineInBullet(sectionAt(headings, i+1)) {
			if m := idBulletPattern.FindStringSubmatch(line); m != nil {
				id = m[1]
			}
		}
		if id == "" {
			continue
		}
		if first, exists := defs[id]; exists {
			out = append(out, violation{
				File: display, Line: i + 1, Rule: "SPEC-ID",
				Message: fmt.Sprintf("duplicate definition of %s (first at line %d)", id, first),
			})
			continue
		}
		defs[id] = i + 1
	}

	for i, line := range lines {
		for _, ref := range xrefPattern.FindAllString(line, -1) {
			parts := strings.SplitN(ref, "#", 2)
			if len(parts) != 2 {
				continue
			}
			target, exists := known[parts[0]]
			if !exists {
				out = append(out, violation{
					File: display, Line: i + 1, Rule: "SPEC-XREF",
					Message: fmt.Sprintf("cross-reference %q names an unknown spec", ref),
				})
				continue
			}
			if !target[parts[1]] {
				out = append(out, violation{
					File: display, Line: i + 1, Rule: "SPEC-XREF",
					Message: fmt.Sprintf("cross-reference %q names an undefined id", ref),
				})
			}
		}
	}
	return out
}

// checkLanguage looks for the forbidden Portuguese vocabulary outside fenced
// code, inline code and the definitional glossary table.
func checkLanguage(display string, lines []string, g glossary) []violation {
	var out []violation
	inFence := false
	inGlossary := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if strings.HasPrefix(trimmed, "**Glossary.**") {
			inGlossary = true
			continue
		}
		if strings.HasPrefix(trimmed, "**Tool.**") {
			inGlossary = false
			continue
		}
		if inGlossary {
			continue
		}
		text := inlineCode.ReplaceAllString(line, "")
		for _, forbidden := range g.Forbidden {
			if containsWord(text, forbidden) {
				out = append(out, violation{
					File: display, Line: i + 1, Rule: "SPEC-LANG",
					Message: fmt.Sprintf("forbidden Portuguese or non-canonical term %q", forbidden),
				})
			}
		}
	}
	return out
}

func containsWord(text, word string) bool {
	lowerText := strings.ToLower(text)
	lowerWord := strings.ToLower(word)
	offset := 0
	for {
		index := strings.Index(lowerText[offset:], lowerWord)
		if index < 0 {
			return false
		}
		index += offset
		before := index == 0 || !isWordRune(lastRune(lowerText[:index]))
		afterIndex := index + len(lowerWord)
		after := afterIndex >= len(lowerText) || !isWordRune(firstRune(lowerText[afterIndex:]))
		if before && after {
			return true
		}
		offset = index + len(lowerWord)
		if offset >= len(lowerText) {
			return false
		}
	}
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}

func firstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

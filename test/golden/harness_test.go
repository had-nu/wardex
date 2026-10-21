//go:build golden

// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package golden

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	// goldenVersion is the version the harness binary is built with. The
	// normaliser replaces it with <VERSION> in captured output.
	goldenVersion = "0.0.0-golden"
	// updateEnv, when set to 1, rewrites want/ instead of comparing.
	updateEnv = "GOLDEN_UPDATE"
)

var binaryPath string

// TestMain builds the CLI once with the release flags, so every case runs the
// same binary. The harness is black box by design: it only uses the command
// line, so it survives the package moves of the modularisation.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "wardex-golden-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "golden: temporary directory: %v\n", err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(root, "wardex")

	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "golden: working directory: %v\n", err)
		os.Exit(1)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))

	build := exec.Command("go", "build",
		"-trimpath",
		"-ldflags=-s -w -buildid= -X main.Version="+goldenVersion,
		"-o", binaryPath,
		".")
	build.Dir = repoRoot
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "golden: build the CLI: %v\n", err)
		_ = os.RemoveAll(root)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}

// caseFile is the declarative description of one case.
type caseFile struct {
	ID        string   `yaml:"id"`
	Flow      string   `yaml:"flow"`
	Args      []string `yaml:"args"`
	Outputs   []string `yaml:"outputs"`
	Normalise []string `yaml:"normalise"`
	// KnownDefect records an issue id when want/ currently captures a defect.
	// The field does not change the comparison; it records why the golden
	// looks wrong, so the case is not "fixed" by accident.
	KnownDefect string `yaml:"known_defect"`
	// Env extends the fixed environment. Use it for deterministic fixture
	// secrets, never for machine-specific values.
	Env map[string]string `yaml:"env"`
}

// result is the normalised outcome of one execution.
type result struct {
	Stdout string
	Stderr string
	Exit   int
	Files  map[string]string
}

func TestGolden(t *testing.T) {
	update := os.Getenv(updateEnv) == "1"

	for _, path := range discoverCases(t) {
		spec := readCaseFile(t, path)
		t.Run(spec.Flow+"/"+spec.ID, func(t *testing.T) {
			caseDir := filepath.Dir(path)
			srcDir := filepath.Join(caseDir, "in")
			if info, err := os.Stat(srcDir); err != nil || !info.IsDir() {
				t.Fatalf("case %s has no in/ directory", spec.ID)
			}

			first := runOnce(t, spec, srcDir)
			second := runOnce(t, spec, srcDir)
			if diff := compareResults(first, second); diff != "" {
				t.Fatalf("case %s is not deterministic (two runs differ):\n%s", spec.ID, diff)
			}

			if spec.KnownDefect != "" {
				t.Logf("known defect: %s", spec.KnownDefect)
			}

			if update {
				writeWant(t, caseDir, first)
				return
			}
			checkWant(t, caseDir, first)
		})
	}
}

// discoverCases returns every case.yaml under cases/, in lexical order, and
// never descends into want/.
func discoverCases(t *testing.T) []string {
	t.Helper()

	var paths []string
	err := filepath.WalkDir("cases", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && entry.Name() == "want" {
			return filepath.SkipDir
		}
		if !entry.IsDir() && entry.Name() == "case.yaml" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("discover cases: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no cases found under cases/")
	}
	sort.Strings(paths)
	return paths
}

func readCaseFile(t *testing.T, path string) caseFile {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var spec caseFile
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if spec.ID == "" || spec.Flow == "" || len(spec.Args) == 0 {
		t.Fatalf("%s: id, flow and args are required", path)
	}
	dir := filepath.Dir(path)
	if got := filepath.Base(dir); got != spec.ID {
		t.Fatalf("%s: id %q does not match the case directory %q", path, spec.ID, got)
	}
	if got := filepath.Base(filepath.Dir(dir)); got != spec.Flow {
		t.Fatalf("%s: flow %q does not match the flow directory %q", path, spec.Flow, got)
	}
	return spec
}

// runOnce copies in/ to an isolated directory, runs the CLI and returns the
// normalised result. The environment is reduced to a fixed set so that the
// developer's shell cannot leak into the golden files.
func runOnce(t *testing.T, spec caseFile, srcDir string) result {
	t.Helper()

	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := copyTree(srcDir, work); err != nil {
		t.Fatalf("copy inputs: %v", err)
	}
	for _, name := range []string{"home", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatalf("prepare %s: %v", name, err)
		}
	}

	cmd := exec.Command(binaryPath, spec.Args...)
	cmd.Dir = work
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(root, "home"),
		"TMPDIR=" + filepath.Join(root, "tmp"),
		"TZ=UTC",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
	for key, value := range spec.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exit := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", spec.Args, err)
		}
		exit = exitErr.ExitCode()
	}

	normaliser := Normaliser{TempDir: root, Version: goldenVersion, Rules: spec.Normalise}
	out := result{Exit: exit, Files: map[string]string{}}
	out.Stdout = mustNormalise(t, normaliser, stdout.String())
	out.Stderr = mustNormalise(t, normaliser, stderr.String())
	for _, name := range spec.Outputs {
		data, err := os.ReadFile(filepath.Join(work, name))
		if err != nil {
			t.Fatalf("declared output %q: %v", name, err)
		}
		out.Files[name] = mustNormalise(t, normaliser, string(data))
	}
	return out
}

func mustNormalise(t *testing.T, normaliser Normaliser, content string) string {
	t.Helper()
	normalised, err := normaliser.Normalise(content)
	if err != nil {
		t.Fatalf("normalise: %v", err)
	}
	return normalised
}

// copyTree copies the regular files and directories of src into dst.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported file %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// writeWant replaces want/ with the captured result.
func writeWant(t *testing.T, caseDir string, captured result) {
	t.Helper()

	wantDir := filepath.Join(caseDir, "want")
	if err := os.RemoveAll(wantDir); err != nil {
		t.Fatalf("clear %s: %v", wantDir, err)
	}
	if err := os.MkdirAll(wantDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", wantDir, err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(wantDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("stdout.txt", captured.Stdout)
	write("stderr.txt", captured.Stderr)
	write("exit", strconv.Itoa(captured.Exit)+"\n")

	if len(captured.Files) == 0 {
		return
	}
	for name, content := range captured.Files {
		target := filepath.Join(wantDir, "files", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("create %s: %v", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
}

// checkWant compares the captured result with the committed want/.
func checkWant(t *testing.T, caseDir string, captured result) {
	t.Helper()

	wantDir := filepath.Join(caseDir, "want")
	readWant := func(name string) string {
		data, err := os.ReadFile(filepath.Join(wantDir, name))
		if err != nil {
			t.Fatalf("missing %s (run 'make golden-update'): %v", filepath.Join(wantDir, name), err)
		}
		return string(data)
	}

	var problems []string
	if diff := diffSummary("stdout", readWant("stdout.txt"), captured.Stdout); diff != "" {
		problems = append(problems, diff)
	}
	if diff := diffSummary("stderr", readWant("stderr.txt"), captured.Stderr); diff != "" {
		problems = append(problems, diff)
	}
	if want := strings.TrimSpace(readWant("exit")); want != strconv.Itoa(captured.Exit) {
		problems = append(problems, fmt.Sprintf("exit: want %s, got %d", want, captured.Exit))
	}

	wantFiles, err := listFiles(filepath.Join(wantDir, "files"))
	if err != nil {
		t.Fatalf("list golden files: %v", err)
	}
	gotNames := make([]string, 0, len(captured.Files))
	for name := range captured.Files {
		gotNames = append(gotNames, name)
	}
	sort.Strings(gotNames)
	if !slices.Equal(wantFiles, gotNames) {
		problems = append(problems, fmt.Sprintf("file set: want %v, got %v", wantFiles, gotNames))
	}
	for _, name := range gotNames {
		data, err := os.ReadFile(filepath.Join(wantDir, "files", filepath.FromSlash(name)))
		if err != nil {
			problems = append(problems, fmt.Sprintf("missing golden file %s", name))
			continue
		}
		if diff := diffSummary("file "+name, string(data), captured.Files[name]); diff != "" {
			problems = append(problems, diff)
		}
	}

	if len(problems) > 0 {
		t.Fatalf("golden mismatch (run 'make golden-update' only with a Golden-Change trailer):\n%s",
			strings.Join(problems, "\n"))
	}
}

// compareResults reports the first difference between two runs, or "" when
// they are equal.
func compareResults(first, second result) string {
	if diff := diffSummary("stdout", first.Stdout, second.Stdout); diff != "" {
		return diff
	}
	if diff := diffSummary("stderr", first.Stderr, second.Stderr); diff != "" {
		return diff
	}
	if first.Exit != second.Exit {
		return fmt.Sprintf("exit: %d then %d", first.Exit, second.Exit)
	}
	a := make([]string, 0, len(first.Files))
	for name := range first.Files {
		a = append(a, name)
	}
	sort.Strings(a)
	b := make([]string, 0, len(second.Files))
	for name := range second.Files {
		b = append(b, name)
	}
	sort.Strings(b)
	if !slices.Equal(a, b) {
		return fmt.Sprintf("file set: %v then %v", a, b)
	}
	for _, name := range a {
		if diff := diffSummary("file "+name, first.Files[name], second.Files[name]); diff != "" {
			return diff
		}
	}
	return ""
}

// diffSummary describes the first differing line of two strings. Golden files
// can be megabytes of JSON, so the whole diff is not printed.
func diffSummary(name, want, got string) string {
	if want == got {
		return ""
	}
	clip := func(s string) string {
		if len(s) > 300 {
			return s[:300] + "…"
		}
		return s
	}
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for i := 0; i < len(wantLines) && i < len(gotLines); i++ {
		if wantLines[i] != gotLines[i] {
			return fmt.Sprintf("%s differs at line %d:\n  want: %s\n  got:  %s",
				name, i+1, clip(wantLines[i]), clip(gotLines[i]))
		}
	}
	return fmt.Sprintf("%s differs in length: want %d line(s), got %d", name, len(wantLines), len(gotLines))
}

// listFiles returns the regular files under root, relative and slash-normalised.
func listFiles(root string) ([]string, error) {
	var names []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

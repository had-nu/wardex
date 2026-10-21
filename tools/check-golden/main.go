// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command check-golden requires a Golden-Change trailer when the inspected
// range modifies a golden file under test/golden/**/want/**.
//
// What it prevents: a golden file records current behaviour, defects included.
// Rewriting want/ without a recorded reason turns a failing test into a passing
// one and leaves no trace of why the expectation moved. The trailer names the
// ADR or issue that justifies the change, for example
// "Golden-Change: ADR-0007" or "Golden-Change: #123".
//
// What it is not: a review. The trailer records that someone decided the new
// output is correct; it does not check the decision. The pull request does.
//
// Usage:
//
//	go run ./tools/check-golden                             # inspect HEAD
//	go run ./tools/check-golden -base main -tip HEAD        # inspect a range
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// trailerKey is the trailer this check looks for. The comparison is
// case-insensitive, as git treats trailer keys.
const trailerKey = "Golden-Change"

// commit is the part of a commit this check needs.
type commit struct {
	SHA     string
	Subject string
	Body    string
}

// isGoldenFile reports whether path is a golden expectation. Only want/ counts:
// a new case adds inputs, and a case.yaml change is visible in review as one
// line, while a rewritten want/ can hide thousands.
func isGoldenFile(path string) bool {
	path = strings.ReplaceAll(path, "\\", "/")
	return strings.HasPrefix(path, "test/golden/") && strings.Contains(path, "/want/")
}

// splitTrailerBlock returns the lines of the final paragraph of msg when that
// paragraph is a git trailer block, and nil when it is not.
//
// Git defines a trailer block as the last paragraph of the message, where every
// line has the form "Key: value". A message that is only trailers counts.
func splitTrailerBlock(msg string) []string {
	msg = strings.ReplaceAll(strings.TrimRight(msg, " \t\r\n"), "\r\n", "\n")
	if msg == "" {
		return nil
	}

	paragraphs := strings.Split(msg, "\n\n")
	lines := strings.Split(paragraphs[len(paragraphs)-1], "\n")

	seen := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, found := strings.Cut(trimmed, ":")
		if !found || strings.TrimSpace(key) == "" {
			return nil
		}
		seen = true
	}
	if !seen {
		return nil
	}
	return lines
}

// goldenChangeValue returns the value of the Golden-Change trailer, if present.
func goldenChangeValue(msg string) (string, bool) {
	for _, line := range splitTrailerBlock(msg) {
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(key), trailerKey) {
			continue
		}
		if value = strings.TrimSpace(value); value != "" {
			return value, true
		}
	}
	return "", false
}

// revisionPattern accepts the characters a git revision name is built from. The
// first character may not be a dash, so a value taken from the command line
// cannot be read as an option by the git invocation below.
var revisionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@^~{}-]*$`)

// checkRevision rejects a revision that git would not accept as a name, or that
// git could read as an option.
func checkRevision(flag, revision string) error {
	if revision == "" {
		return fmt.Errorf("%s is empty", flag)
	}
	if !revisionPattern.MatchString(revision) {
		return fmt.Errorf("%s %q is not a git revision", flag, revision)
	}
	return nil
}

// goldenFilesInRange returns the golden files that base..tip adds or modifies.
// An empty base inspects the single commit at tip, which is all a first push
// has to offer.
func goldenFilesInRange(repoDir, base, tip string) ([]string, error) {
	if err := checkRevision("-tip", tip); err != nil {
		return nil, err
	}

	var args []string
	if base == "" {
		args = []string{"diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "--diff-filter=MD", tip, "--", "test/golden"}
	} else {
		if err := checkRevision("-base", base); err != nil {
			return nil, err
		}
		args = []string{"diff", "--name-only", "--diff-filter=MD", base, tip, "--", "test/golden"}
	}

	var stdout, stderr bytes.Buffer
	// #nosec G204 -- the subcommand and the flags are literals from this file.
	// The only interpolated values are base and tip, which checkRevision has
	// just restricted to names that git cannot read as options.
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}

	var changed []string
	for line := range strings.SplitSeq(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if isGoldenFile(line) {
			changed = append(changed, line)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

// gitLog returns the commits in the range, newest first. An empty base inspects
// the single commit at tip.
func gitLog(repoDir, base, tip string) ([]commit, error) {
	if err := checkRevision("-tip", tip); err != nil {
		return nil, err
	}

	revision := tip
	if base != "" {
		if err := checkRevision("-base", base); err != nil {
			return nil, err
		}
		revision = base + ".." + tip
	}

	args := []string{"log", "--format=%H%x1f%s%x1f%B%x1e", revision}

	var stdout, stderr bytes.Buffer
	// #nosec G204 -- the subcommand and the format are literals from this file.
	// The only interpolated values are base and tip, which checkRevision has
	// just restricted to names that git cannot read as options.
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git log %s: %w: %s", revision, err, strings.TrimSpace(stderr.String()))
	}

	var commits []commit
	for record := range strings.SplitSeq(stdout.String(), "\x1e") {
		fields := strings.SplitN(record, "\x1f", 3)
		if len(fields) == 3 && fields[0] != "" {
			commits = append(commits, commit{SHA: fields[0], Subject: fields[1], Body: fields[2]})
		}
	}
	return commits, nil
}

// run performs the check and writes the report, returning the process exit
// code: 0 when clean, 1 when golden files changed without a trailer, 2 when the
// check itself failed.
func run(repoDir, base, tip string, out io.Writer) int {
	changed, err := goldenFilesInRange(repoDir, base, tip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-golden: %v\n", err)
		return 2
	}
	if len(changed) == 0 {
		return 0
	}

	commits, err := gitLog(repoDir, base, tip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-golden: %v\n", err)
		return 2
	}
	for _, c := range commits {
		if _, ok := goldenChangeValue(c.Body); ok {
			return 0
		}
	}

	fmt.Fprintln(out, "Golden files changed without a Golden-Change trailer:")
	for _, path := range changed {
		fmt.Fprintf(out, "  %s\n", path)
	}
	fmt.Fprintf(out, "\nAdd a trailer naming the ADR or issue that justifies the new expectation,\n"+
		"for example \"Golden-Change: ADR-0007\". A changed expectation without a\n"+
		"recorded reason is a test that agreed to disagree.\n")
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Fprintf(out, "::error file=%s::Golden files changed without a Golden-Change trailer\n", changed[0])
	}
	return 1
}

func main() {
	base := flag.String("base", "", "commit to inspect from, exclusive. Empty inspects -tip only.")
	tip := flag.String("tip", "HEAD", "commit to inspect up to, inclusive.")
	repoDir := flag.String("repo", ".", "path to the git repository")
	flag.Parse()

	os.Exit(run(*repoDir, *base, *tip, os.Stdout))
}

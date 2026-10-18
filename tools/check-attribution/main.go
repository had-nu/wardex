// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command check-attribution reports Co-authored-by trailers that name an AI
// assistant.
//
// What it prevents: a commit that credits an assistant nobody asked to see
// credited. That changes the record of who did the work, and a tool default
// makes the change silently.
//
// What it is not: a security control. The deny list is matched against a
// free-text value, so a determined actor words the trailer so that this does
// not fire. A failure means look at the commit, not that nothing is wrong.
//
// A trailer is attribution, not authorisation. CONTRIBUTING.md records that
// distinction under "Attribution Trailers". This tool does not rewrite history
// and does not remove anything: it reads the range it is given, which in CI is
// the range a pull request proposes to merge.
//
// Usage:
//
//	go run ./tools/check-attribution                             # inspect HEAD
//	go run ./tools/check-attribution -base main~1 -tip main      # inspect a range
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// assistantMarkers are substrings matched, case-insensitively, against the
// value of a Co-authored-by trailer.
//
// The list holds the identities coding assistants have used as their own
// trailer by default. It matches on the address rather than the display name
// because "Cursor" and "Devin" are also company names, and a display-name match
// would flag a legitimate human co-author.
//
// Adding an entry is a policy change. See CONTRIBUTING.md before editing.
var assistantMarkers = []string{
	"@anthropic.com", // Claude
	"@opencode.ai",   // OpenCode
	"@openai.com",    // ChatGPT, Codex
	"@aider.chat",    // Aider
	"@devin.ai",      // Devin
	"@cursor.sh",     // Cursor
	"198982749+copilot@users.noreply.github.com", // GitHub Copilot
}

// commit is the part of a commit this check needs.
type commit struct {
	SHA     string
	Subject string
	Body    string
}

// finding is one commit in the inspected range carrying a flagged trailer.
type finding struct {
	SHA     string
	Subject string
	Trailer string
}

// splitTrailerBlock returns the lines of the final paragraph of msg when that
// paragraph is a git trailer block, and nil when it is not.
//
// Git defines a trailer block as the last paragraph of the message, where every
// line has the form "Key: value". A message that is only trailers counts, which
// is why one paragraph is accepted rather than requiring two.
func splitTrailerBlock(msg string) []string {
	// Normalise line endings before looking for the blank line that separates
	// paragraphs: in a CRLF message the bytes are "\r\n\r\n", which does not
	// contain "\n\n".
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
			// A line that is not "Key: value" means this paragraph is body
			// text, so any Co-authored-by line earlier in the message is part
			// of the message rather than a trailer.
			return nil
		}
		seen = true
	}
	if !seen {
		return nil
	}
	return lines
}

// coAuthoredValues returns the value of every Co-authored-by trailer in the
// message. The key is matched case-insensitively because git accepts any
// capitalisation of it.
func coAuthoredValues(msg string) []string {
	lines := splitTrailerBlock(msg)

	var values []string
	for _, line := range lines {
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "co-authored-by") {
			continue
		}
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

// isAssistant reports whether a trailer value names an AI assistant.
func isAssistant(value string) bool {
	lowered := strings.ToLower(value)
	for _, marker := range assistantMarkers {
		if strings.Contains(lowered, strings.ToLower(marker)) {
			return true
		}
	}
	return false
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

// gitLog returns the commits in the range, newest first. An empty base inspects
// the single commit at tip, which is all a first push has to offer.
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

	// The field and record separators are ASCII control characters that do not
	// occur in a commit subject or message, so a message containing newlines,
	// equals signs or NUL bytes still splits correctly.
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

// scan inspects the range in repoDir and returns every flagged trailer.
func scan(repoDir, base, tip string) ([]finding, error) {
	commits, err := gitLog(repoDir, base, tip)
	if err != nil {
		return nil, err
	}

	var findings []finding
	for _, c := range commits {
		for _, value := range coAuthoredValues(c.Body) {
			if isAssistant(value) {
				findings = append(findings, finding{
					SHA:     c.SHA,
					Subject: c.Subject,
					Trailer: "Co-authored-by: " + value,
				})
			}
		}
	}
	return findings, nil
}

// inCI reports whether the process runs inside a GitHub Actions runner, where an
// ::error:: annotation becomes an entry in the pull request conversation.
func inCI() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

// annotation renders a value for a GitHub workflow command.
//
// The runner gives %, CR and LF a special meaning, so they are escaped as its
// documentation requires. Angle brackets are replaced rather than escaped: a
// message containing them is truncated by the runner, which reduced the whole
// annotation to the first word. The full trailer still goes to standard output,
// where nothing truncates it.
func annotation(value string) string {
	return strings.NewReplacer(
		"%", "%25",
		"\r", "%0D",
		"\n", "%0A",
		"<", "(",
		">", ")",
	).Replace(value)
}

// run performs the scan and writes the report, returning the process exit code:
// 0 when clean, 1 when trailers were flagged, 2 when the check itself failed.
func run(repoDir, base, tip string, out io.Writer) int {
	findings, err := scan(repoDir, base, tip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-attribution: %v\n", err)
		return 2
	}
	if len(findings) == 0 {
		return 0
	}

	for _, f := range findings {
		short := f.SHA
		if len(short) > 8 {
			short = short[:8]
		}
		fmt.Fprintf(out, "%s  %s\n    %s\n", short, f.Subject, f.Trailer)
		if inCI() {
			fmt.Fprintf(out, "::error file=CONTRIBUTING.md::Commit %s adds a trailer naming an AI assistant: %s\n",
				short, annotation(f.Trailer))
		}
	}

	fmt.Fprintf(out, "\n%d commit(s) credit an AI assistant. A trailer is attribution and not\n"+
		"authorisation: see CONTRIBUTING.md, \"Attribution Trailers\". Remove the trailer\n"+
		"or record the agreement that justifies it.\n", len(findings))
	return 1
}

func main() {
	base := flag.String("base", "", "commit to inspect from, exclusive. Empty inspects -tip only.")
	tip := flag.String("tip", "HEAD", "commit to inspect up to, inclusive.")
	repoDir := flag.String("repo", ".", "path to the git repository")
	flag.Parse()

	os.Exit(run(*repoDir, *base, *tip, os.Stdout))
}

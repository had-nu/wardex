// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitTrailerBlock(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want int
	}{
		{
			name: "trailer block after prose",
			msg:  "fix: something\n\nWhy it matters.\n\nSigned-off-by: Someone <s@example.invalid>",
			want: 1,
		},
		{
			name: "message is only trailers",
			msg:  "Co-authored-by: A B <a@example.invalid>",
			want: 1,
		},
		{
			name: "several trailers",
			msg:  "subject\n\nCo-authored-by: A B <a@example.invalid>\nSigned-off-by: C D <c@example.invalid>",
			want: 2,
		},
		{
			name: "trailer-like line in prose is not a trailer",
			// The last paragraph is not "Key: value" throughout, so the whole
			// message has no trailer block and the line above must not count.
			msg:  "subject\n\nCo-authored-by: A B <a@example.invalid>\n\nSee the note above.\n",
			want: 0,
		},
		{
			name: "empty message",
			msg:  "",
			want: 0,
		},
		{
			name: "only whitespace",
			msg:  "   \n\n\t\n",
			want: 0,
		},
		{
			name: "crlf line endings",
			msg:  "subject\r\n\r\nCo-authored-by: A B <a@example.invalid>\r\n",
			want: 1,
		},
		{
			name: "comment line inside the block",
			msg:  "subject\n\n# a comment\nCo-authored-by: A B <a@example.invalid>",
			want: 2,
		},
		{
			name: "line without a key ends the block",
			msg:  "subject\n\nCo-authored-by: A B <a@example.invalid>\nnot a trailer at all",
			want: 0,
		},
		{
			name: "value containing a colon",
			msg:  "subject\n\nCo-authored-by: Bot <bot@example.invalid>",
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := splitTrailerBlock(tt.msg)
			if len(lines) != tt.want {
				t.Fatalf("splitTrailerBlock() returned %d lines, want %d\nlines: %q",
					len(lines), tt.want, lines)
			}
		})
	}
}

func TestCoAuthoredValues(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want []string
	}{
		{
			name: "canonical",
			msg:  "s\n\nCo-authored-by: A B <a@example.invalid>",
			want: []string{"A B <a@example.invalid>"},
		},
		{
			name: "lower case key, as GitHub squash merges write it",
			msg:  "s\n\nco-authored-by: A B <a@example.invalid>",
			want: []string{"A B <a@example.invalid>"},
		},
		{
			name: "trailing whitespace is trimmed",
			msg:  "s\n\nCo-authored-by:   A B <a@example.invalid>   \n",
			want: []string{"A B <a@example.invalid>"},
		},
		{
			name: "no trailer",
			msg:  "s\n\nSigned-off-by: A B <a@example.invalid>",
			want: nil,
		},
		{
			name: "empty value is dropped",
			msg:  "s\n\nCo-authored-by:",
			want: nil,
		},
		{
			name: "signed-off-by is not co-authorship",
			msg:  "s\n\nCo-authored-by: A B <a@example.invalid>\nSigned-off-by: C D <c@example.invalid>",
			want: []string{"A B <a@example.invalid>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coAuthoredValues(tt.msg)
			if len(got) != len(tt.want) {
				t.Fatalf("coAuthoredValues() = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("coAuthoredValues() = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestIsAssistant(t *testing.T) {
	flagged := []string{
		"Claude Opus 4.8 (1M context) <noreply@anthropic.com>",
		"claude <noreply@anthropic.com>",
		"opencode <assistant@opencode.ai>",
		"OpenCode <ASSISTANT@OPENCODE.AI>",
		"ChatGPT <noreply@openai.com>",
		"Aider <aider@aider.chat>",
		"Devin <devin@devin.ai>",
		"Cursor <cursor@cursor.sh>",
		"Copilot <198982749+Copilot@users.noreply.github.com>",
	}
	for _, value := range flagged {
		t.Run("flags "+value, func(t *testing.T) {
			if !isAssistant(value) {
				t.Fatalf("isAssistant(%q) = false, want true", value)
			}
		})
	}

	// A human co-author, including one whose display name collides with a
	// product name, must not be flagged. Getting this wrong would block a
	// legitimate commit.
	allowed := []string{
		"André Ataíde <66465162+had-nu@users.noreply.github.com>",
		"dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
		"André Ataíde <andre_ataide@proton.me>",
		"Cursor Software Inc <legal@cursor.com>",
		"Devin Corp <hello@devin.io>",
		"Someone <someone@example.invalid>",
	}
	for _, value := range allowed {
		t.Run("allows "+value, func(t *testing.T) {
			if isAssistant(value) {
				t.Fatalf("isAssistant(%q) = true, want false", value)
			}
		})
	}
}

// fixtureCommit is one commit created in the throwaway repository the scan
// tests build.
type fixtureCommit struct {
	subject string
	body    string
}

const assistantTrailer = "Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"

// newFixtureRepo creates a repository whose history contains one commit of each
// kind the check has to tell apart, and returns its path.
//
// The fixture is self-contained on purpose. A test that scanned the real
// history of this repository would pass or fail depending on whether the
// checkout was shallow, which is exactly the kind of check that looks armed and
// is not.
func newFixtureRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	commits := []fixtureCommit{
		{subject: "feat: first change", body: "No trailers here."},
		{subject: "feat: clean commit", body: "Signed-off-by: Test <test@example.invalid>"},
		{subject: "feat: human co-author", body: "Co-authored-by: André Ataíde <66465162+had-nu@users.noreply.github.com>"},
		{subject: "build(deps): bump something", body: "Co-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"},
		{subject: "docs: mentions a trailer in prose", body: "The line\n\nCo-authored-by: A B <a@example.invalid>\n\nis documentation, not a trailer."},
		{subject: "feat: assistant trailer", body: "The work.\n\n" + assistantTrailer},
	}

	gitRun(t, dir, "init", "-q", "-b", "main")

	tracked := filepath.Join(dir, "tracked.txt")
	for i, c := range commits {
		// Each commit needs a change to record, so write the file as we go
		// rather than once at the start.
		if err := os.WriteFile(tracked, []byte(c.subject+"\n"), 0o600); err != nil {
			t.Fatalf("write fixture file: %v", err)
		}

		gitRun(t, dir, "add", "-A")
		args := []string{"commit", "-q", "-m", c.subject}
		if c.body != "" {
			args = append(args, "-m", c.body)
		}
		gitRun(t, dir, args...)
		_ = i
	}
	return dir
}

// gitRun runs a git command in dir with a fixed identity, so the fixture does
// not depend on the developer's global configuration.
func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid",
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "no-global-config"),
		"GIT_CONFIG_SYSTEM="+filepath.Join(dir, "no-system-config"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func TestScanFlagsTheAssistantCommitOnly(t *testing.T) {
	dir := newFixtureRepo(t)

	findings, err := scan(dir, "", "HEAD")
	if err != nil {
		t.Fatalf("scan() error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("scan() returned %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Subject != "feat: assistant trailer" {
		t.Fatalf("scan() flagged %q, want %q", findings[0].Subject, "feat: assistant trailer")
	}
	if findings[0].Trailer != assistantTrailer {
		t.Fatalf("scan() trailer = %q, want %q", findings[0].Trailer, assistantTrailer)
	}
}

func TestScanRespectsTheRange(t *testing.T) {
	dir := newFixtureRepo(t)

	// The offending commit is the most recent one. Inspecting everything up to
	// its parent must find nothing; inspecting the full range must find it.
	base := gitOut(t, dir, "rev-parse", "HEAD~1")

	findings, err := scan(dir, base, "HEAD")
	if err != nil {
		t.Fatalf("scan() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("scan(base=HEAD~1) returned %d findings, want 1", len(findings))
	}

	findings, err = scan(dir, "HEAD", "HEAD~1")
	if err != nil {
		t.Fatalf("scan() error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("scan(HEAD..HEAD~1) returned %d findings, want 0", len(findings))
	}
}

func TestCheckRevision(t *testing.T) {
	accepted := []string{
		"HEAD",
		"main",
		"feat/cra-conformance",
		"HEAD~1",
		"HEAD^",
		"v2.6.0",
		"5583f4b1c2a9d0e7",
		"HEAD@{1}",
		"release/2.x",
	}
	for _, revision := range accepted {
		t.Run("accepts "+revision, func(t *testing.T) {
			if err := checkRevision("-base", revision); err != nil {
				t.Fatalf("checkRevision(%q) = %v, want nil", revision, err)
			}
		})
	}

	// Every rejected value here would be read by git as something other than a
	// name. A leading dash makes it an option; a space splits it into an
	// argument list; a quote and a dollar are shell metacharacters that must
	// not survive even though this tool passes arguments without a shell.
	rejected := []string{
		"",
		"-",
		"--all",
		"--upload-pack=touch /tmp/x",
		"HEAD --format=%B",
		"HEAD;rm -rf /",
		"HEAD|cat",
		"$(id)",
		"`id`",
		"HEAD\n--all",
		"-tip",
		"@{-1}",
	}
	for _, revision := range rejected {
		t.Run("rejects "+revision, func(t *testing.T) {
			if err := checkRevision("-base", revision); err == nil {
				t.Fatalf("checkRevision(%q) = nil, want an error", revision)
			}
		})
	}
}

func TestScanRejectsRevisionsThatGitWouldReadAsOptions(t *testing.T) {
	dir := newFixtureRepo(t)

	// Both flags reach a git command line. A value beginning with a dash would
	// be read as an option, so a caller could make the tool run a git it never
	// chose. Asserting only that an error comes back would not prove anything:
	// git rejects an unknown option itself, so the error has to be the one this
	// tool raises before running anything.
	canary := filepath.Join(t.TempDir(), "canary")
	injected := "--upload-pack=touch " + canary

	for _, tt := range []struct{ name, base, tip string }{
		{"option in base", injected, "HEAD"},
		{"option in tip", "HEAD", injected},
		{"option in both", injected, injected},
		{"bare dash in tip", "HEAD", "-"},
		{"space in tip", "HEAD", "HEAD --format=%B"},
		{"empty tip", "HEAD", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := scan(dir, tt.base, tt.tip)
			if err == nil {
				t.Fatalf("scan(base=%q, tip=%q) accepted an option as a revision", tt.base, tt.tip)
			}
			if !strings.Contains(err.Error(), "is not a git revision") &&
				!strings.Contains(err.Error(), "is empty") {
				t.Fatalf("scan(base=%q, tip=%q) failed at git rather than at validation: %v",
					tt.base, tt.tip, err)
			}
		})
	}

	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatalf("the injected command ran: %s exists", canary)
	}
}

func TestScanAcceptsRealRevisionNames(t *testing.T) {
	dir := newFixtureRepo(t)

	head := gitOut(t, dir, "rev-parse", "HEAD")
	tagged := gitOut(t, dir, "rev-parse", "HEAD~1")

	if _, err := scan(dir, tagged, head); err != nil {
		t.Fatalf("scan() rejected a real revision: %v", err)
	}
	if _, err := scan(dir, "HEAD", head); err != nil {
		t.Fatalf("scan() rejected a symbolic name: %v", err)
	}
	if _, err := scan(dir, "", "main"); err != nil {
		t.Fatalf("scan() rejected a branch name: %v", err)
	}
}

func TestAnnotationIsNotTruncatedByTheRunner(t *testing.T) {
	// The runner truncated a message containing angle brackets down to its
	// first word, which made the annotation read "Commit ". Percent, CR and LF
	// carry their own meaning, so all of them are escaped.
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"angle brackets", "<noreply@anthropic.com>", "(noreply@anthropic.com)"},
		{"percent", "100% done", "100%25 done"},
		{"carriage return", "a\rb", "a%0Db"},
		{"newline", "a\nb", "a%0Ab"},
		{"all of them", "50%\r\n<x>", "50%25%0D%0A(x)"},
		{"plain", "nothing to escape", "nothing to escape"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := annotation(tt.value); got != tt.want {
				t.Fatalf("annotation(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}

	// Nothing that reaches the runner may start a new line or a new command.
	for _, value := range []string{"a\nb", "a\rb", "::error x", "::warning y"} {
		if got := annotation(value); strings.ContainsAny(got, "\r\n") {
			t.Fatalf("annotation(%q) still contains a line break: %q", value, got)
		}
	}
}

func TestRunExitCodes(t *testing.T) {
	dir := newFixtureRepo(t)
	base := gitOut(t, dir, "rev-parse", "HEAD~1")

	var out strings.Builder
	if code := run(dir, base, "HEAD", &out); code != 1 {
		t.Fatalf("run() with a finding = %d, want 1\noutput: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "feat: assistant trailer") {
		t.Fatalf("run() did not name the commit it flagged:\n%s", out.String())
	}

	out.Reset()
	if code := run(dir, "HEAD", "HEAD", &out); code != 0 {
		t.Fatalf("run() clean = %d, want 0\noutput: %s", code, out.String())
	}
	if out.String() != "" {
		t.Fatalf("run() clean wrote to output: %q", out.String())
	}

	// A broken check must be distinguishable from a clean one, so that a
	// failure to read history never reads as a pass.
	out.Reset()
	if code := run(filepath.Join(dir, "does-not-exist"), "", "HEAD", &out); code != 2 {
		t.Fatalf("run() on a missing repository = %d, want 2", code)
	}
}

// gitOut runs a git command in dir and returns its trimmed standard output.
func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "no-global-config"),
		"GIT_CONFIG_SYSTEM="+filepath.Join(dir, "no-system-config"),
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

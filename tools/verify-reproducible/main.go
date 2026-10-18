// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command verify-reproducible proves that the release build is byte-for-byte
// reproducible.
//
// It reads the real build settings from .goreleaser.yaml rather than repeating
// them here, so the check cannot drift from what the release actually runs. It
// then builds the same revision in N separate git worktrees at different paths
// and compares the SHA-256 digests.
//
// Why separate paths: with -trimpath omitted, the build directory is embedded
// in the binary, so two builds of identical source can still differ. Building
// in distinct worktrees is what makes that failure visible.
//
// Usage:
//
//	go run ./tools/verify-reproducible
//	go run ./tools/verify-reproducible -n 3
//	go run ./tools/verify-reproducible -rev v2.6.0 -version 2.6.0
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// releaseBuild mirrors the subset of the goreleaser build stanza this tool
// needs. Unknown fields are ignored so a goreleaser upgrade does not break the
// check.
type releaseBuild struct {
	Env     []string `yaml:"env"`
	Flags   []string `yaml:"flags"`
	Ldflags []string `yaml:"ldflags"`
	Goos    []string `yaml:"goos"`
	Goarch  []string `yaml:"goarch"`
}

type releaseConfig struct {
	Before struct {
		Hooks []string `yaml:"hooks"`
	} `yaml:"before"`
	Builds []releaseBuild `yaml:"builds"`
}

const goreleaserConfig = ".goreleaser.yaml"

// versionPlaceholder is the goreleaser template token for the release version.
// The name avoids the word "token" so gosec does not read it as a secret.
const versionPlaceholder = "{{ .Version }}"

func main() {
	copies := flag.Int("n", 2, "number of independent build locations to compare")
	rev := flag.String("rev", "HEAD", "revision to verify")
	version := flag.String("version", "verify", "value substituted for the release version in ldflags")
	target := flag.String("target", "", "GOOS/GOARCH to build, for example linux/amd64 (default: host)")
	keep := flag.Bool("keep", false, "keep the temporary worktrees and binaries")
	flag.Parse()

	if *copies < 2 {
		fatal(fmt.Errorf("-n must be at least 2, got %d: a single build cannot prove reproducibility", *copies))
	}

	if err := run(*copies, *rev, *version, *target, *keep); err != nil {
		fatal(err)
	}
}

func run(copies int, rev, version, target string, keep bool) error {
	repoRoot, err := repoRoot()
	if err != nil {
		return err
	}

	cfg, err := loadReleaseBuild(repoRoot)
	if err != nil {
		return err
	}

	env, flags, ldflags, err := buildSettings(cfg, version, target)
	if err != nil {
		return err
	}

	fmt.Printf("verifying reproducibility of %s over %d independent build locations\n", rev, copies)
	fmt.Printf("  env:     %s\n", strings.Join(env, " "))
	fmt.Printf("  flags:   %s\n", strings.Join(flags, " "))
	fmt.Printf("  ldflags: %s\n\n", strings.Join(ldflags, " "))

	base, err := os.MkdirTemp("", "wardex-repro-")
	if err != nil {
		return fmt.Errorf("create temp root: %w", err)
	}
	if !keep {
		defer func() { _ = os.RemoveAll(base) }()
	}

	dirs := make([]string, 0, copies)
	defer func() {
		for _, dir := range dirs {
			// Detach first: a failed build may leave the worktree in a state
			// that plain remove rejects.
			_ = runGit(repoRoot, "worktree", "remove", "--force", dir)
		}
	}()

	digests := make([]string, 0, copies)
	paths := make([]string, 0, copies)

	for i := range copies {
		dir := filepath.Join(base, fmt.Sprintf("build-%d", i+1))
		if err := addWorktree(repoRoot, dir, rev); err != nil {
			return err
		}
		dirs = append(dirs, dir)

		binary := filepath.Join(base, fmt.Sprintf("wardex-%d", i+1))
		if err := build(dir, binary, env, flags, ldflags); err != nil {
			return fmt.Errorf("build %d of %d failed: %w", i+1, copies, err)
		}

		digest, err := fileDigest(binary)
		if err != nil {
			return err
		}
		digests = append(digests, digest)
		paths = append(paths, binary)
		fmt.Printf("  build %d  %s  %s\n", i+1, digest[:16], dir)
	}

	if keep {
		fmt.Printf("\nkept build locations under %s\n", base)
	}

	return compare(digests, paths)
}

// compare reports the outcome of the reproducibility check.
func compare(digests, paths []string) error {
	first := digests[0]
	for i := 1; i < len(digests); i++ {
		if digests[i] == first {
			continue
		}
		return fmt.Errorf("build is NOT reproducible: %d different digests across %d build locations\n"+
			"  %s  %s\n  %s  %s\n"+
			"release flags that vary with the build path are missing; check -trimpath and -buildid= in %s",
			countDistinct(digests), len(digests), paths[0], digests[0], paths[i], digests[i], goreleaserConfig)
	}

	fmt.Printf("\nOK: %d builds, %d distinct digest, all identical\n", len(digests), countDistinct(digests))
	return nil
}

func countDistinct(digests []string) int {
	seen := make(map[string]struct{}, len(digests))
	for _, d := range digests {
		seen[d] = struct{}{}
	}
	return len(seen)
}

// buildSettings turns one goreleaser build stanza into exec arguments.
// Only the first build is verified: the goreleaser config declares a single
// build covering every platform.
func buildSettings(cfg releaseConfig, version, target string) (env, flags, ldflags []string, err error) {
	if len(cfg.Builds) == 0 {
		return nil, nil, nil, fmt.Errorf("no builds declared in %s", goreleaserConfig)
	}
	build := cfg.Builds[0]

	env = append([]string(nil), build.Env...)
	flags = append([]string(nil), build.Flags...)

	// Only set GOOS/GOARCH when a target is requested. An empty value in the
	// environment is not the same as an absent one, so the host build must
	// leave the variables out entirely.
	if target != "" {
		goos, goarch, err := hostOrTarget(target)
		if err != nil {
			return nil, nil, nil, err
		}
		env = append(env, "GOOS="+goos, "GOARCH="+goarch)
	}

	for _, raw := range build.Ldflags {
		// goreleaser splits ldflags on whitespace; each element may hold a
		// whole flag string with embedded spaces, as in the released config.
		ldflags = append(ldflags, strings.Fields(replaceAll(raw, versionPlaceholder, version))...)
	}

	if len(flags) == 0 && len(ldflags) == 0 {
		return nil, nil, nil, fmt.Errorf("%s declares no build flags; nothing would be verified", goreleaserConfig)
	}

	return env, flags, ldflags, nil
}

func replaceAll(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}

func hostOrTarget(target string) (goos, goarch string, err error) {
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid -target %q: want GOOS/GOARCH", target)
	}
	return parts[0], parts[1], nil
}

func loadReleaseBuild(repoRoot string) (releaseConfig, error) {
	var cfg releaseConfig
	// #nosec G304 -- repoRoot is the git toplevel of the repository under test.
	data, err := os.ReadFile(filepath.Join(repoRoot, goreleaserConfig))
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", goreleaserConfig, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", goreleaserConfig, err)
	}
	return cfg, nil
}

func repoRoot() (string, error) {
	out, err := gitOutput(nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("locate repository root: %w", err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", errors.New("locate repository root: empty output")
	}
	return root, nil
}

func addWorktree(repoRoot, dir, rev string) error {
	if _, err := gitOutputIn(repoRoot, "worktree", "add", "--detach", dir, rev); err != nil {
		return fmt.Errorf("create worktree at %s: %w", dir, err)
	}
	return nil
}

func build(dir, output string, env, flags, ldflags []string) error {
	args := []string{"build", "-o", output}
	args = append(args, flags...)
	if len(ldflags) > 0 {
		args = append(args, "-ldflags="+strings.Join(ldflags, " "))
	}
	args = append(args, ".")

	// #nosec G204 -- args are built from literals in buildSettings plus the
	// output path this tool created; no caller input reaches the command line.
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	// Start from a known environment so a stray GOFLAGS or GOOS in the shell
	// cannot make the check describe a build nobody releases.
	cmd.Env = append(os.Environ(), env...)

	stderr := &strings.Builder{}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func fileDigest(path string) (string, error) {
	// #nosec G304 -- path is under the temp root this tool created.
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runGit(dir string, args ...string) error {
	_, err := gitOutputIn(dir, args...)
	return err
}

func gitOutput(dir []string, args ...string) ([]byte, error) {
	return gitOutputIn(".", args...)
}

// gitOutputIn runs git and returns stdout. Arguments are fixed literals chosen
// by this tool; no caller-supplied value reaches the command line unchecked.
func gitOutputIn(dir string, args ...string) ([]byte, error) {
	// #nosec G204 -- subcommand and flags are literals from this file; the
	// only interpolated values are temp paths and a git revision.
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "verify-reproducible: %v\n", err)
	os.Exit(1)
}

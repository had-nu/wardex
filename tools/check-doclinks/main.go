// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Command check-doclinks verifies that every relative link in the repository's
// Markdown resolves to a file that exists.
//
// The repository once held four directories of documentation, with
// specifications spread across three of them and two of them untracked because
// unanchored .gitignore rules matched them. Consolidating that was worth little
// if the next move could break a link silently, so the invariant is enforced.
//
// A link is relative to the document that holds it. A document inside doc/ that
// links to README.md is pointing at doc/README.md, which does not exist, and
// several did exactly that. This is the failure this catches.
//
// Usage:
//
//	go run ./tools/check-doclinks
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// linkPattern matches an inline Markdown link target. Reference-style links
// ([text][ref] with the target defined elsewhere) are not resolved, because
// finding the definition needs a real parser and no document in this repository
// uses one.
var linkPattern = regexp.MustCompile(`\[[^\]]*\]\(\s*([^)\s]+)`)

// skippedDirs are build output and tool caches, never documentation.
var skippedDirs = map[string]bool{
	".git": true, ".ua": true, "dist": true, "node_modules": true, "research": true,
}

// brokenLink is one relative target that does not resolve.
type brokenLink struct {
	Document string
	Target   string
}

func main() {
	root := flag.String("root", ".", "repository root to scan")
	flag.Parse()

	broken, scanned, links, err := check(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-doclinks: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("checked %d relative link(s) in %d document(s)\n", links, scanned)
	if len(broken) == 0 {
		return
	}
	for _, b := range broken {
		fmt.Printf("%s: %s\n", b.Document, b.Target)
	}
	fmt.Fprintf(os.Stderr, "\n%d link(s) do not resolve\n", len(broken))
	os.Exit(1)
}

// check walks the Markdown under root and returns the links that do not resolve.
func check(root string) (broken []brokenLink, scanned, links int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && skippedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}

		// #nosec G304 G122 -- the path comes from a walk rooted at -root and
		// filtered to Markdown. The tool reads the repository it was pointed at
		// and nothing else, which is the whole of its function.
		source, readErr := os.Open(path)
		if readErr != nil {
			return readErr
		}
		defer func() { _ = source.Close() }()

		scanned++

		var doc string
		document := bufio.NewScanner(source)
		for document.Scan() {
			for _, raw := range linkPattern.FindAllStringSubmatch(document.Text(), -1) {
				target := raw[1]
				if !isRelative(target) {
					continue
				}
				links++
				clean := target
				if i := strings.IndexAny(clean, "#?"); i >= 0 {
					clean = clean[:i]
				}
				if clean == "" {
					// An in-document anchor.
					continue
				}
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				if !resolves(filepath.Join(root, filepath.Dir(rel), clean)) {
					if doc == "" {
						doc = filepath.ToSlash(rel)
					}
					broken = append(broken, brokenLink{Document: doc, Target: target})
				}
			}
		}
		return document.Err()
	})
	return broken, scanned, links, err
}

// isRelative reports whether a link target points inside the repository and so
// has to resolve. Anything with a scheme, a leading slash, or no path at all is
// not the checker's business.
func isRelative(target string) bool {
	switch {
	case target == "":
		return false
	case strings.HasPrefix(target, "http://"), strings.HasPrefix(target, "https://"),
		strings.HasPrefix(target, "mailto:"), strings.HasPrefix(target, "ftp://"):
		return false
	case strings.HasPrefix(target, "/"), strings.HasPrefix(target, "#"),
		strings.HasPrefix(target, "//"):
		return false
	}
	// A Windows drive letter is not a relative repository path.
	return len(target) < 2 || target[1] != ':'
}

// resolves reports whether a cleaned relative target exists. A directory counts:
// a link to a folder is legitimate and every viewer handles it.
func resolves(candidate string) bool {
	_, err := os.Stat(candidate)
	return err == nil
}

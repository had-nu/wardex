// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Gate class profiles (L3): risk classes pr|deploy|nightly select the severity
// of each sub-exam. Defaults follow the spec matrix; config gate.classes
// overrides individual exams per class.

package orchestrator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/had-nu/wardex/v2/config"
)

// examSeverity values, duplicated from config constants to avoid a config
// import cycle in tests; keep in sync.
type examSeverity int

const (
	severityBlock examSeverity = iota
	severityAdvisory
	severityOff
)

func parseSeverity(s string) (examSeverity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case config.SevBlock:
		return severityBlock, nil
	case config.SevAdvisory:
		return severityAdvisory, nil
	case config.SevOff:
		return severityOff, nil
	}
	return severityBlock, fmt.Errorf("invalid exam severity %q (use block|advisory|off)", s)
}

// classProfile is the resolved severity for every sub-exam of a risk class.
type classProfile struct {
	name          string
	integrity     examSeverity
	policy        examSeverity
	freshness     examSeverity
	activeExploit examSeverity
}

// defaultClassProfiles encodes the spec L3 matrix.
//
//	| exam            | pr        | deploy             | nightly      |
//	|-----------------|-----------|--------------------|--------------|
//	| integrity       | block     | block              | off          |
//	| policy          | block     | block              | off (report) |
//	| freshness       | advisory  | block              | advisory     |
//	| active_exploit  | off       | block              | off (report) |
var defaultClassProfiles = map[string]classProfile{
	config.ClassPR: {
		name:          config.ClassPR,
		integrity:     severityBlock,
		policy:        severityBlock,
		freshness:     severityAdvisory,
		activeExploit: severityOff,
	},
	config.ClassDeploy: {
		name:          config.ClassDeploy,
		integrity:     severityBlock,
		policy:        severityBlock,
		freshness:     severityBlock,
		activeExploit: severityBlock,
	},
	config.ClassNightly: {
		name:          config.ClassNightly,
		integrity:     severityOff,
		policy:        severityOff,
		freshness:     severityAdvisory,
		activeExploit: severityOff,
	},
}

// validClasses returns the sorted list of known class names.
func validClasses() []string {
	out := make([]string, 0, len(defaultClassProfiles))
	for c := range defaultClassProfiles {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// resolveClassProfile computes the effective profile for className by starting
// from the class defaults and overlaying config gate.classes overrides. An
// empty or unknown class name yields an error (deploy is the caller-side
// default). Unknown exam keys are rejected.
func resolveClassProfile(className string, cfg *config.Config) (classProfile, error) {
	if className == "" {
		className = config.ClassDeploy
	}
	base, ok := defaultClassProfiles[className]
	if !ok {
		return classProfile{}, fmt.Errorf("unknown gate class %q (use %s)", className, strings.Join(validClasses(), "|"))
	}

	over, err := overlayClassOverrides(className, cfg)
	if err != nil {
		return classProfile{}, err
	}

	if sev, ok := over[config.ExamIntegrity]; ok {
		base.integrity = sev
	}
	if sev, ok := over[config.ExamPolicy]; ok {
		base.policy = sev
	}
	if sev, ok := over[config.ExamFreshness]; ok {
		base.freshness = sev
	}
	if sev, ok := over[config.ExamActiveExploit]; ok {
		base.activeExploit = sev
	}

	return base, nil
}

// overlayClassOverrides parses and validates cfg.ReleaseGate.Classes for the
// given class into a severity map.
func overlayClassOverrides(className string, cfg *config.Config) (map[string]examSeverity, error) {
	out := map[string]examSeverity{}
	if cfg == nil || cfg.ReleaseGate.Classes == nil {
		return out, nil
	}
	byClass, ok := cfg.ReleaseGate.Classes[className]
	if !ok {
		return out, nil
	}

	known := map[string]bool{
		config.ExamIntegrity:     true,
		config.ExamPolicy:        true,
		config.ExamFreshness:     true,
		config.ExamActiveExploit: true,
	}
	for exam, sev := range byClass {
		if !known[exam] {
			return nil, fmt.Errorf("unknown gate exam %q for class %q (use integrity|policy|freshness|active_exploit)", exam, className)
		}
		parsed, err := parseSeverity(sev)
		if err != nil {
			return nil, fmt.Errorf("class %q exam %q: %w", className, exam, err)
		}
		out[exam] = parsed
	}
	return out, nil
}

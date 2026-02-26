package correlator

import (
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

// MatchResult stores the details of a matching operation
type MatchResult struct {
	Matched         bool
	Confidence      string // "high" | "low"
	MatchedDomains  []string
	MatchedKeywords []string
}

// matchDomains checks if explicitly declared domains match the AnnexA control
func matchDomains(existing model.ExistingControl, annexA model.AnnexAControl) ([]string, bool) {
	var matched []string
	annexMap := make(map[string]bool)
	for _, d := range annexA.Domains {
		annexMap[strings.ToLower(strings.TrimSpace(d))] = true
	}

	for _, d := range existing.Domains {
		if annexMap[strings.ToLower(strings.TrimSpace(d))] {
			matched = append(matched, d)
		}
	}
	return matched, len(matched) > 0
}

// matchKeywords checks for keyword occurrences in Name and Description
func matchKeywords(existing model.ExistingControl, annexA model.AnnexAControl) ([]string, bool) {
	var matched []string
	content := strings.ToLower(existing.Name + " " + existing.Description)

	for _, kw := range annexA.Keywords {
		if strings.Contains(content, strings.ToLower(kw)) {
			matched = append(matched, kw)
		}
	}
	return matched, len(matched) > 0
}

// Match evaluates whether an existing control addresses an AnnexA control
func Match(existing model.ExistingControl, annexA model.AnnexAControl) MatchResult {
	// 1. Declarative match (high confidence)
	if matchedDomains, ok := matchDomains(existing, annexA); ok {
		return MatchResult{
			Matched:         true,
			Confidence:      "high",
			MatchedDomains:  matchedDomains,
			MatchedKeywords: nil,
		}
	}

	// 2. Inferential match (low confidence)
	if matchedKeywords, ok := matchKeywords(existing, annexA); ok {
		return MatchResult{
			Matched:         true,
			Confidence:      "low",
			MatchedDomains:  nil,
			MatchedKeywords: matchedKeywords,
		}
	}

	return MatchResult{Matched: false}
}

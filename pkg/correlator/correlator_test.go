package correlator_test

import (
	"testing"

	"github.com/had-nu/wardex/pkg/correlator"
	"github.com/had-nu/wardex/pkg/model"
)

func TestMatchHighConfidence(t *testing.T) {
	ext := model.ExistingControl{ID: "C1", Domains: []string{"access_control"}}
	anx := model.CatalogControl{ID: "A.9", Domains: []string{"access_control"}}

	res := correlator.Match(ext, anx)
	if !res.Matched || res.Confidence != "high" {
		t.Fatalf("expected high confidence match, got: %+v", res)
	}
}

func TestMatchLowConfidence(t *testing.T) {
	ext := model.ExistingControl{
		ID:          "C2",
		Name:        "Firewall Config",
		Description: "Blocks unwanted traffic",
	}
	anx := model.CatalogControl{
		ID:       "A.13",
		Keywords: []string{"firewall", "network"},
	}

	res := correlator.Match(ext, anx)
	if !res.Matched || res.Confidence != "low" {
		t.Fatalf("expected low confidence match, got: %+v", res)
	}
	if len(res.MatchedKeywords) != 1 || res.MatchedKeywords[0] != "firewall" {
		t.Fatalf("expected firewall keyword match")
	}
}

func TestMatchNoMatch(t *testing.T) {
	ext := model.ExistingControl{ID: "C3", Name: "Coffee Policy", Domains: []string{"hr"}}
	anx := model.CatalogControl{ID: "A.1", Keywords: []string{"firewall"}, Domains: []string{"technical"}}

	res := correlator.Match(ext, anx)
	if res.Matched {
		t.Fatalf("expected no match, got: %+v", res)
	}
}

func TestCorrelator(t *testing.T) {
	cat := []model.CatalogControl{
		{ID: "A.1", Domains: []string{"access"}},
		{ID: "A.2", Keywords: []string{"log"}},
	}

	c := correlator.New(cat)
	exts := []model.ExistingControl{
		{ID: "C1", Domains: []string{"access"}},
		{ID: "C2", Description: "centralized log server"},
	}

	mappings := c.Correlate(exts)
	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
}

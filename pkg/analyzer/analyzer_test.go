package analyzer_test

import (
	"strings"
	"testing"

	"github.com/had-nu/wardex/pkg/analyzer"
	"github.com/had-nu/wardex/pkg/model"
)

func TestAnalyzer_Covered(t *testing.T) {
	cat := []model.AnnexAControl{{ID: "A.1", BaseScore: 5.0}}

	controls := []model.ExistingControl{
		{
			ID: "C1", Maturity: 3,
			Evidences: []model.Evidence{{Type: "policy", Ref: "link"}},
		},
	}

	maps := []model.Mapping{
		{ExistingControlID: "C1", AnnexAControlID: "A.1", Confidence: "high"},
	}

	a := analyzer.New(cat, maps, controls)
	findings := a.Analyze()

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding")
	}

	if findings[0].Status != model.StatusCovered {
		t.Errorf("expected status covered, got %s", findings[0].Status)
	}
}

func TestAnalyzer_Partial_LowConfidence(t *testing.T) {
	cat := []model.AnnexAControl{{ID: "A.1", BaseScore: 5.0}}

	controls := []model.ExistingControl{
		{
			ID: "C1", Maturity: 4,
			Evidences: []model.Evidence{{Type: "policy", Ref: "link"}},
		},
	}

	maps := []model.Mapping{
		{ExistingControlID: "C1", AnnexAControlID: "A.1", Confidence: "low"},
	}

	a := analyzer.New(cat, maps, controls)
	findings := a.Analyze()

	if findings[0].Status != model.StatusPartial {
		t.Errorf("expected status partial, got %s", findings[0].Status)
	}

	if len(findings[0].GapReasons) == 0 || !strings.Contains(findings[0].GapReasons[0], "low confidence") {
		t.Errorf("expected low confidence reason, got %v", findings[0].GapReasons)
	}
}

func TestAnalyzer_Gap(t *testing.T) {
	cat := []model.AnnexAControl{{ID: "A.1", BaseScore: 5.0}}

	a := analyzer.New(cat, nil, nil)
	findings := a.Analyze()

	if findings[0].Status != model.StatusGap {
		t.Errorf("expected status gap, got %s", findings[0].Status)
	}
}

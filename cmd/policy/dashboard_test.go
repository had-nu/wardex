package policy

import (
	"testing"

	policyfiles "github.com/had-nu/wardex/v2/internal/policy"
)

func testPolicyDomains() []*policyfiles.DomainFile {
	return []*policyfiles.DomainFile{{
		Domain: "protect",
		Controls: []policyfiles.Control{
			{ID: "A.8.1", Title: "Control one", Status: policyfiles.StatusCompliant},
			{ID: "A.8.2", Title: "Control two", Status: policyfiles.StatusNonCompliant},
		},
	}}
}

func TestBuildPolicyListDashboard(t *testing.T) {
	dashboard := buildPolicyListDashboard("frameworks/iso27001", testPolicyDomains())
	if dashboard.Summary.Decision != "REVIEW" || len(dashboard.Findings) != 2 {
		t.Fatalf("unexpected policy dashboard: %+v", dashboard)
	}
}

func TestBuildPolicyExpiryDashboard(t *testing.T) {
	dashboard := buildPolicyExpiryDashboard("frameworks/iso27001", []expiredPolicyException{{
		ControlID: "A.8.1", Domain: "protect", Expiry: "2020-01-01", Reason: "internal note",
	}})
	if dashboard.Summary.Decision != "EXPIRED" || dashboard.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected expiry dashboard: %+v", dashboard)
	}
}

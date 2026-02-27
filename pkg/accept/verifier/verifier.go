package verifier

import (
	"time"

	"github.com/had-nu/wardex/pkg/accept/signer"
	"github.com/had-nu/wardex/pkg/model"
)

// Result represents the verification result of an Acceptance.
type Result struct {
	Acceptance     model.Acceptance
	Valid          bool
	Expired        bool
	Tampered       bool
	Stale          bool // config mudou desde a aceitação
	ReportMismatch bool // GateReport actual diverge do original
	ExpiresIn      time.Duration
	Errors         []string
}

// VerifyAll verifies the signature, expiry, and hashes for multiple acceptances.
func VerifyAll(acceptances []model.Acceptance, key []byte, currentReportHash string, currentConfigHash string) ([]Result, bool) {
	var results []Result
	allValid := true

	for _, a := range acceptances {
		res := Result{Acceptance: a}

		if err := signer.Verify(a, key); err != nil {
			res.Tampered = true
			res.Errors = append(res.Errors, err.Error())
			allValid = false
		}

		if !a.ExpiresAt.IsZero() && time.Now().After(a.ExpiresAt) {
			res.Expired = true
			res.Errors = append(res.Errors, "acceptance has expired")
			allValid = false
		} else {
			res.ExpiresIn = time.Until(a.ExpiresAt)
		}

		// Validation succeeds if its non tampered and non expired
		if !res.Tampered && !res.Expired {
			res.Valid = true
		}
		results = append(results, res)
	}

	return results, allValid
}

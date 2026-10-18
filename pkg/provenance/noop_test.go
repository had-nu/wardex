// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"context"
	"testing"
)

func TestNoopAnchorerMarksResultsAsDryRun(t *testing.T) {
	anchorer := &noopAnchorer{}
	ctx := context.Background()

	submit, err := anchorer.Submit(ctx, []byte("hash"), "release")
	if err != nil || !submit.DryRun || submit.Found {
		t.Fatalf("unexpected submit result: %+v, err=%v", submit, err)
	}
	attested, err := anchorer.SubmitAttested(ctx, []byte("hash"), "release", []byte("attestation"))
	if err != nil || !attested.DryRun || attested.Found {
		t.Fatalf("unexpected attested result: %+v, err=%v", attested, err)
	}
	verify, err := anchorer.Verify(ctx, []byte("hash"))
	if err != nil || !verify.DryRun || verify.Found {
		t.Fatalf("unexpected verify result: %+v, err=%v", verify, err)
	}
	wait, err := anchorer.WaitForAnchor(ctx, []byte("hash"))
	if err != nil || !wait.DryRun || wait.Found {
		t.Fatalf("unexpected wait result: %+v, err=%v", wait, err)
	}
	health, err := anchorer.Status(ctx)
	if err != nil || !health.DryRun {
		t.Fatalf("unexpected health result: %+v, err=%v", health, err)
	}
}

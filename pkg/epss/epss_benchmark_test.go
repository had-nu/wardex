// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package epss

import (
	"fmt"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/model"
)

func benchEnrichment(n int) model.EPSSEnrichmentFile {
	f := model.EPSSEnrichmentFile{
		GeneratedAt: "2026-08-20T00:00:00Z",
		Provenance:  map[string]string{"tool": "wardex", "version": "2.5.0"},
	}
	for i := range n {
		f.Enrichments = append(f.Enrichments, model.EPSSEnrichment{
			CVE:   fmt.Sprintf("CVE-2026-%05d", i),
			Score: 0.0001 * float64(i),
		})
	}
	return f
}

func BenchmarkSign(b *testing.B) {
	f := benchEnrichment(100)
	key := []byte("wardex-benchmark-secret")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(f, key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	f := benchEnrichment(100)
	key := []byte("wardex-benchmark-secret")
	sig, _ := Sign(f, key)
	f.Signature = sig
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(f, key); err != nil {
			b.Fatal(err)
		}
	}
}

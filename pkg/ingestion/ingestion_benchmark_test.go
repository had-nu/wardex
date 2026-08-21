// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ingestion

import (
	"fmt"
	"os"
	"testing"
)

// Fixtures are written once per benchmark run to keep the parsed-input
// generation out of the measured loop. Benchmarks cover the three supported
// reader formats plus the merged LoadMany path. Files are written into the
// package working directory because SafeReadFile confines reads to the cwd.
func benchFixture(b *testing.B, name, content string) string {
	b.Helper()
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.Remove(name) })
	return name
}

func yamlBenchContent(controls int) string {
	var s string
	s += "controls:\n"
	for i := range controls {
		s += fmt.Sprintf("  - id: \"CTRL-%04d\"\n    name: \"Control %d\"\n    maturity: 3\n    layer: implemented\n    domains: [\"organizational\"]\n", i, i)
	}
	return s
}

func jsonBenchContent(controls int) string {
	s := `{"controls": [`
	for i := range controls {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf(`{"id": "CTRL-%04d", "name": "Control %d", "maturity": 3, "layer": "implemented"}`, i, i)
	}
	return s + `]}`
}

func csvBenchContent(controls int) string {
	s := "id,name,description,maturity,domains,context_weight\n"
	for i := range controls {
		s += fmt.Sprintf("%d,Control %d,Desc,3,organizational,1.0\n", i, i)
	}
	return s
}

func BenchmarkLoadYAML(b *testing.B) {
	path := benchFixture(b, "bench.yaml", yamlBenchContent(100))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := loadYAML(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadJSON(b *testing.B) {
	path := benchFixture(b, "bench.json", jsonBenchContent(100))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := loadJSON(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadCSV(b *testing.B) {
	path := benchFixture(b, "bench.csv", csvBenchContent(100))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := loadCSV(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadMany(b *testing.B) {
	names := []string{"bench-many-0.yaml", "bench-many-1.yaml", "bench-many-2.yaml", "bench-many-3.yaml"}
	for _, name := range names {
		benchFixture(b, name, yamlBenchContent(25))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := LoadMany(names); err != nil {
			b.Fatal(err)
		}
	}
}

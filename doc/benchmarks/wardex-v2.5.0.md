# Benchmarks — Baseline v2.5.0

Baseline benchmark results recorded for the Wardex v2.5.0 release
(Go 1.27.0, linux/amd64, GOTOOLCHAIN=auto).

These are the first benchmarks for `pkg/ingestion` and `pkg/epss`. They
establish the comparison baseline for the §5.1 hardening criterion ("melhoria
≥ 0.5% ou sem regressão > 1%"): a future migration must not regress any of the
numbers below by more than 1%.

## pkg/ingestion

| Benchmark        | ns/op     | B/op   | allocs/op |
| ---------------- | --------- | ------ | --------- |
| BenchmarkLoadYAML (100 controls) | 2,584,729 | 408,852 | 6,213 |
| BenchmarkLoadJSON (100 controls) |   364,657 | 130,734 |   280 |
| BenchmarkLoadCSV  (100 controls) |   266,829 |  81,320 |   379 |
| BenchmarkLoadMany (4×25 YAML)    | 3,163,162 | 463,887 | 6,847 |

## pkg/epss

| Benchmark            | ns/op   | B/op  | allocs/op |
| -------------------- | ------- | ----- | --------- |
| BenchmarkSign   (100 enrichments) | 100,118 | 17,207 | 323 |
| BenchmarkVerify (100 enrichments) |  85,807 | 17,206 | 323 |

## Reproduction

```bash
GOTOOLCHAIN=auto go test -run=^$ -bench=. -benchmem ./pkg/ingestion/ ./pkg/epss/
```

Fixture generation is excluded from the measured loop; ingestion benchmarks
write into the package working directory because `SafeReadFile` confines reads
to the process cwd.
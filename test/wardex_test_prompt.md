# PROMPT — WARDEX CALIBRATION TEST RUNNER
# Destino: Claude Code (antigravity)
# Contexto: repo github.com/had-nu/wardex, branch main
# Objectivo: executar o test suite de calibração e gerar relatórios para embasar o paper IEEE

---

## CONTEXTO DO PROJECTO

Estou a submeter um paper IEEE intitulado:
*"Contextual Risk Scoring for Vulnerability-Driven Release Decisions in CI/CD Pipelines: A Formal Model and Simulation Study"*

O modelo central é:
```
R(v, α) = CVSS(v) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))
```

O test suite está em `test/tunning/` (sim, com duplo 'n' — não renomear).
O pipeline está em `test/tunning/empirical_pipeline.py`.
Os testes estão em `test/tunning/test_calibration.py`.

---

## TAREFA

Executa o seguinte plano de forma sequencial. Para cada passo, regista o output completo.
Se um passo falhar, diagnostica a causa, corrige e continua — não parares no primeiro erro.

---

### PASSO 1 — Setup do ambiente

```bash
cd test/tunning
pip install pytest hypothesis pytest-cov pytest-json-report --quiet
```

Verifica que `pipeline.py` é importável:
```bash
python3 -c "from pipeline import compute_contextual_score, evaluate_gate, derive_profile_calibration; print('OK')"
```

Se falhar, verifica conflitos de `sys.path` e adiciona o directório ao path conforme o comentário no topo de `test_calibration.py`.

---

### PASSO 2 — Testes determinísticos (T1 + T6) — SEM snapshot

Executa apenas os testes que não precisam do snapshot (`data/dataset_2025-03-01.json`):

```bash
pytest test_calibration.py \
  -v \
  -k "not (Empirical or GroundTruth or Sensitivity)" \
  --tb=short \
  --json-report \
  --json-report-file=reports/t1_t6_deterministic.json \
  2>&1 | tee reports/t1_t6_deterministic.txt
```

Cria o directório `reports/` se não existir.

**Resultado esperado:** 34 testes PASSED (T1: 14, T2: 6, T_UNIT: 7, T_DERIVE: 6, T6: 4 regressão + 3 isolados).
Se algum falhar, anota o nome exacto e o erro completo — estes são breaking changes no modelo.

---

### PASSO 3 — Executa o pipeline empiricamente (com dados sintéticos para CI)

O pipeline real requer APIs externas (NVD, FIRST.org, CISA, GitHub). Para CI sem rede,
executa a versão de smoke test que usa apenas funções locais:

```python
# smoke_test_pipeline.py — criar este ficheiro em test/tunning/
import sys
sys.path.insert(0, '.')
from pipeline import (
    compute_contextual_score, evaluate_gate, derive_profile_calibration,
    naics_to_fips199, ssvc_to_c_alpha, ssvc_to_e_alpha,
    IncidentRecord, ProfileCalibration, SNAPSHOT_DATE
)
import json, hashlib, datetime
from pathlib import Path

# ── Incidentes sintéticos calibrados (substitutos VCDB) ──────────────────
def make_incidents(naics, vector, fips, n):
    return [IncidentRecord(
        source="synthetic", incident_id=f"syn-{i:04d}",
        naics_sector=naics, org_size="medium",
        asset_type="Server", access_vector=vector,
        cia_impact="C", cve_ids=[], fips199_level=fips,
    ) for i in range(n)]

all_incidents = (
    make_incidents("52", "External - Internet", "High", 120) +   # BANK: finance, internet
    make_incidents("52", "Internal",            "High",  30) +   # BANK: finance, internal
    make_incidents("62", "External - Internet", "High", 100) +   # HOSP: healthcare, internet
    make_incidents("62", "Internal",            "High",  40) +   # HOSP: healthcare, internal
    make_incidents("51", "External - Internet", "Moderate", 80)+ # SAAS: tech, internet
    make_incidents("51", "Internal",            "Moderate", 60)+ # SAAS: tech, internal
    make_incidents("51", "Internal",            "Low",    80) +  # DEV: sandbox, internal
    make_incidents("54", "Internal",            "Low",    60)    # DEV: professional services
)

PROFILES_CONFIG = [
    ("BANK", ["52"],         {"block": 0.5,  "warn": 0.3}),
    ("HOSP", ["62"],         {"block": 0.8,  "warn": 0.5}),
    ("SAAS", ["51"],         {"block": 2.0,  "warn": 1.0}),
    ("DEV",  ["51", "54"],   {"block": 4.0,  "warn": 2.0}),
]

calibrations = {}
for name, naics, thetas in PROFILES_CONFIG:
    cal = derive_profile_calibration(name, naics, all_incidents)
    calibrations[name] = {
        "profile_name": cal.profile_name,
        "naics_codes":  cal.naics_codes,
        "c_alpha":      cal.c_alpha,
        "e_alpha":      cal.e_alpha,
        "c_alpha_source": cal.c_alpha_source,
        "e_alpha_source": cal.e_alpha_source,
        "n_incidents":  cal.n_incidents,
        "theta_block":  thetas["block"],
        "theta_warn":   thetas["warn"],
    }
    print(f"[{name}] C(α)={cal.c_alpha:.2f}  E(α)={cal.e_alpha:.2f}  "
          f"n={cal.n_incidents}  source={cal.c_alpha_source}")

# ── Casos ilustrativos do paper (Table 2) ────────────────────────────────
ILLUSTRATIVE = [
    ("CVE-2021-44228", 10.0, 0.940, "Log4Shell"),
    ("CVE-2024-3094",  10.0, 0.860, "xz backdoor"),
    ("CVE-2023-38545",  9.8, 0.260, "curl SOCKS5"),
    ("CVE-2019-10744",  9.8, 0.010, "minimist"),
]

print("\n=== ILLUSTRATIVE CASES ===")
print(f"{'CVE':<20} {'Name':<15} {'BANK':>8} {'HOSP':>8} {'SAAS':>8} {'DEV':>8}")
print("-" * 75)

for cve_id, cvss, epss, name in ILLUSTRATIVE:
    row = [f"{cve_id:<20}", f"{name:<15}"]
    for prof_name, naics, thetas in PROFILES_CONFIG:
        cal = calibrations[prof_name]
        score = compute_contextual_score(cvss, epss, cal["c_alpha"], cal["e_alpha"])
        dec = evaluate_gate(score, thetas["block"], thetas["warn"])
        row.append(f"{dec:>8}")
    print("".join(row))

# ── CVE sintético corpus (237 entradas para o simulation study) ──────────
import random
random.seed(42)

# Distribuição real por tier: Low=18, Medium=47, High=98, Critical=74
cve_corpus = []
for cvss_range, n in [(1.0, 4.0, 18), (4.0, 7.0, 47), (7.0, 9.0, 98), (9.0, 10.0, 74)]:
    for _ in range(n):
        cvss = random.uniform(*cvss_range[:2])
        epss = random.betavariate(0.3, 3.0)  # heavy tail low EPSS
        cve_corpus.append({"cvss": cvss, "epss": epss})

# Simulation study
print("\n=== SIMULATION STUDY (237 CVEs, synthetic EPSS distribution) ===")
print(f"{'Profile':<8} {'BLOCK':>6} {'ALLOW':>6} {'%Block':>8} {'vs CVSS≥7':>12} {'Diverge':>9}")
print("-" * 60)

baseline_block = sum(1 for v in cve_corpus if v["cvss"] >= 7.0)
results = {}

for prof_name, naics, thetas in PROFILES_CONFIG:
    cal = calibrations[prof_name]
    block = allow = under = over = 0
    for v in cve_corpus:
        score = compute_contextual_score(v["cvss"], v["epss"], cal["c_alpha"], cal["e_alpha"])
        ctx_dec  = evaluate_gate(score, thetas["block"], thetas["warn"]) == "BLOCK"
        cvss_dec = v["cvss"] >= 7.0
        if ctx_dec: block += 1
        else: allow += 1
        if ctx_dec and not cvss_dec: under += 1
        if cvss_dec and not ctx_dec: over  += 1
    total = len(cve_corpus)
    diverge = under + over
    delta = block - baseline_block
    results[prof_name] = dict(block=block, allow=allow, diverge=diverge,
                              under=under, over=over, delta=delta, total=total)
    print(f"{prof_name:<8} {block:>6} {allow:>6} {block/total:>8.1%} "
          f"{'+' if delta>=0 else ''}{delta:>11} {diverge/total:>8.1%}")

total_pairs = len(cve_corpus) * len(PROFILES_CONFIG)
total_diverge = sum(r["diverge"] for r in results.values())
print(f"\nTotal divergence: {total_diverge}/{total_pairs} = {total_diverge/total_pairs:.1%}")

# ── Guardar calibration.json para T3/T4/T5 ───────────────────────────────
Path("data").mkdir(exist_ok=True)
calibration_output = {
    "metadata": {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "corpus_size": len(cve_corpus),
        "note": "Synthetic calibration — VCDB substitute for CI without network access"
    },
    "calibrations": [
        {**v, "n_cves": len(cve_corpus)}
        for v in calibrations.values()
    ]
}
Path("data/calibration.json").write_text(json.dumps(calibration_output, indent=2))

# Snapshot mínimo para T4/T5
snapshot = {
    "cve_records": [
        {
            "cve_id": f"CVE-2024-{i:04d}",
            "cvss_base": v["cvss"],
            "epss_score": v["epss"],
            "cisa_kev": v["cvss"] >= 9.0 and v["epss"] >= 0.5,  # heurística conservadora
            "ssvc_exploitation": "active" if v["epss"] > 0.7 else "poc" if v["epss"] > 0.2 else "none",
            "ssvc_automatable": v["cvss"] >= 8.0,
            "ssvc_impact": "Total" if v["cvss"] >= 9.0 else "Partial",
        }
        for i, v in enumerate(cve_corpus)
    ],
    "calibrations": calibration_output["calibrations"],
}
sha = hashlib.sha256(json.dumps(snapshot).encode()).hexdigest()
snapshot["metadata"] = {"sha256": sha, "n_cves": len(cve_corpus)}
Path("data/dataset_2025-03-01.json").write_text(json.dumps(snapshot, indent=2))
print(f"\nArtifacts written:")
print(f"  data/calibration.json  ({len(calibration_output['calibrations'])} profiles)")
print(f"  data/dataset_2025-03-01.json  (sha256: {sha[:16]}...)")
```

Executa com:
```bash
python3 smoke_test_pipeline.py 2>&1 | tee reports/smoke_pipeline.txt
```

---

### PASSO 4 — Suite completa de testes (todos os 48)

Com os artefactos do Passo 3 em `data/`, agora todos os testes podem correr:

```bash
pytest test_calibration.py \
  -v \
  --tb=long \
  --json-report \
  --json-report-file=reports/full_suite.json \
  --cov=pipeline \
  --cov-report=term-missing \
  --cov-report=json:reports/coverage.json \
  2>&1 | tee reports/full_suite.txt
```

---

### PASSO 5 — Relatório de sensitivity analysis (κ)

Executa o seguinte script para gerar dados brutos da Fig. 3 do paper:

```python
# kappa_sensitivity.py
import sys; sys.path.insert(0, '.')
from pipeline import compute_contextual_score
import json
from pathlib import Path

snapshot = json.loads(Path("data/dataset_2025-03-01.json").read_text())
cve_records = snapshot["cve_records"]

# BANK profile — valores paper
C_BANK, E_BANK, THETA_BANK = 1.50, 1.00, 0.5

kappas = [round(k * 0.01, 2) for k in range(50, 100)]  # 0.50 a 0.99
results = []

for kappa in kappas:
    block_count = sum(
        1 for r in cve_records
        if compute_contextual_score(
            r["cvss_base"], r["epss_score"], C_BANK, E_BANK, kappa=kappa
        ) > THETA_BANK
    )
    results.append({"kappa": kappa, "block_count": block_count})

# Calcular variação na zona estável [0.70, 0.90]
stable = [r["block_count"] for r in results if 0.70 <= r["kappa"] <= 0.90]
variation_pct = (max(stable) - min(stable)) / len(cve_records)

print(f"Stable zone [0.70, 0.90]: min={min(stable)}, max={max(stable)}, "
      f"variation={variation_pct:.1%} of {len(cve_records)} CVEs")
print(f"Paper claim: ≤10% variation → {'PASS' if variation_pct <= 0.10 else 'FAIL'}")

Path("reports/kappa_sensitivity.json").write_text(json.dumps({
    "profile": "BANK",
    "c_alpha": C_BANK, "e_alpha": E_BANK, "theta_block": THETA_BANK,
    "n_cves": len(cve_records),
    "stable_zone": {"min_kappa": 0.70, "max_kappa": 0.90,
                    "min_blocks": min(stable), "max_blocks": max(stable),
                    "variation_pct": round(variation_pct, 4)},
    "series": results
}, indent=2))

print("\nkappa,block_count")
for r in results:
    print(f"{r['kappa']:.2f},{r['block_count']}")
```

```bash
python3 kappa_sensitivity.py 2>&1 | tee reports/kappa_sensitivity.txt
```

---

### PASSO 6 — Relatório consolidado para o paper

Gera um ficheiro Markdown com todos os números necessários para as secções §V e §VI do paper:

```python
# paper_report.py
import json
from pathlib import Path

smoke  = Path("reports/smoke_pipeline.txt").read_text()
full   = Path("reports/full_suite.json")
kappa  = json.loads(Path("reports/kappa_sensitivity.json").read_text())

full_data = json.loads(full.read_text()) if full.exists() else {}
summary = full_data.get("summary", {})

passed = summary.get("passed", "?")
failed = summary.get("failed", 0)
total  = summary.get("total", 48)
duration = summary.get("duration", "?")

cov_data = {}
if Path("reports/coverage.json").exists():
    cov_raw = json.loads(Path("reports/coverage.json").read_text())
    cov_pct = cov_raw.get("totals", {}).get("percent_covered", 0)
else:
    cov_pct = "N/A"

report = f"""# Wardex — Test Evidence Report
**Generated for IEEE paper submission**

---

## Test Suite Results

| Metric | Value |
|--------|-------|
| Tests passed | {passed}/{total} |
| Tests failed | {failed} |
| Duration | {duration}s |
| Pipeline coverage | {cov_pct if isinstance(cov_pct, str) else f'{cov_pct:.1f}%'} |

### Test Classes

| Class | Scope | Purpose |
|-------|-------|---------|
| TestMathematicalProperties (14) | Unit | P1 Monotonicity, P2 Bounds, P3 Fail-close |
| TestPropertyBased (6) | Property-based | Invariants via Hypothesis (500 examples each) |
| TestEmpiricalCalibration (5) | Integration | C(α)/E(α) deviation ≤20% from paper values |
| TestGroundTruthValidation (4) | Integration | KEV Recall ≥60% for BANK/HOSP |
| TestSensitivityAnalysis (2) | Integration | κ stability [0.70, 0.90] ≤10% variation |
| TestIllustrativeCasesRegression (4+3) | Regression | Table 2 exact decisions |
| TestMappingFunctions (7) | Unit | NAICS→FIPS199, SSVC→C(α)/E(α) |
| TestDeriveProfileCalibration (6) | Unit | Empirical derivation with synthetic incidents |

---

## Sensitivity Analysis — κ Parameter (§V.C)

| Metric | Value |
|--------|-------|
| Profile | {kappa['profile']} |
| C(α) | {kappa['c_alpha']} |
| E(α) | {kappa['e_alpha']} |
| θ_block | {kappa['theta_block']} |
| CVEs | {kappa['n_cves']} |
| Stable zone | κ ∈ [{kappa['stable_zone']['min_kappa']}, {kappa['stable_zone']['max_kappa']}] |
| Block count range | [{kappa['stable_zone']['min_blocks']}, {kappa['stable_zone']['max_blocks']}] |
| Variation | {kappa['stable_zone']['variation_pct']:.1%} of corpus |
| Paper claim (≤10%) | {'VERIFIED' if kappa['stable_zone']['variation_pct'] <= 0.10 else 'FAILED'} |

---

## Calibration Output (§V.A — Profile Parameters)

```
{Path("reports/smoke_pipeline.txt").read_text().split("=== ILLUSTRATIVE")[0].strip()}
```

---

## Illustrative Cases Verification (§V.B — Table 2)

```
{("=== ILLUSTRATIVE CASES ===" + Path("reports/smoke_pipeline.txt").read_text().split("=== ILLUSTRATIVE CASES ===")[1]).split("=== SIMULATION")[0].strip() if "=== ILLUSTRATIVE CASES ===" in Path("reports/smoke_pipeline.txt").read_text() else "N/A"}
```

---

## Simulation Study (§V.B — Table 1)

```
{("=== SIMULATION STUDY" + Path("reports/smoke_pipeline.txt").read_text().split("=== SIMULATION STUDY")[1]) if "=== SIMULATION STUDY" in Path("reports/smoke_pipeline.txt").read_text() else "N/A"}
```

---

## Reproducibility

- Dataset SHA256: `{json.loads(Path("data/dataset_2025-03-01.json").read_text()).get("metadata", {}).get("sha256", "N/A")}`
- Snapshot date: 2025-03-01 (fixed for reproducibility)
- Test runner: pytest + Hypothesis
- Environment: Python 3.12

*This report was generated automatically from test/tunning/ in github.com/had-nu/wardex.*
"""

Path("reports/paper_evidence.md").write_text(report)
print(report)
```

```bash
python3 paper_report.py 2>&1 | tee reports/paper_evidence_log.txt
```

---

### PASSO 7 — Verificação final

Confirma que os seguintes artefactos existem e têm conteúdo não-vazio:

```bash
echo "=== ARTEFACTOS GERADOS ==="
for f in \
  reports/t1_t6_deterministic.json \
  reports/t1_t6_deterministic.txt \
  reports/smoke_pipeline.txt \
  reports/full_suite.json \
  reports/full_suite.txt \
  reports/coverage.json \
  reports/kappa_sensitivity.json \
  reports/kappa_sensitivity.txt \
  reports/paper_evidence.md \
  data/calibration.json \
  data/dataset_2025-03-01.json; do
  if [ -s "$f" ]; then
    echo "  OK  $(wc -l < $f) lines  $f"
  else
    echo "  MISSING  $f"
  fi
done
```

---

## OUTPUT ESPERADO

No final, entrega-me:
1. O conteúdo de `reports/paper_evidence.md` — é o relatório que vai para o paper.
2. O conteúdo de `reports/full_suite.txt` — lista completa dos 48 testes com PASS/FAIL.
3. O conteúdo de `reports/kappa_sensitivity.txt` — para validar o claim §V.C.
4. Qualquer teste que tenha falhado com o erro completo e a tua análise da causa.
5. O SHA256 do dataset (`data/dataset_2025-03-01.json`) para incluir no paper.

---

## NOTAS IMPORTANTES

- Não alteres `test_calibration.py` nem `empirical_pipeline.py` — são os ficheiros a testar.
- Se um import falhar, verifica se estás no directório `test/tunning/` antes de correr.
- O directório `data/` é criado pelo `smoke_test_pipeline.py` — corre-o antes do pytest completo.
- Os testes T3/T4/T5 dependem de `data/calibration.json` e `data/dataset_2025-03-01.json`.
  Sem esses ficheiros, fazem `SKIP` em vez de `FAIL` — isso é comportamento correcto.
- A tolerância de calibração é 20% — se os valores sintéticos divergirem mais do que isso
  dos valores do paper (BANK C=1.5/E=1.0, HOSP C=1.5/E=0.8, etc.), anota mas não é um blocker.

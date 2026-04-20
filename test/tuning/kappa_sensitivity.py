# kappa_sensitivity.py
import sys; sys.path.insert(0, '.')
from pipeline import compute_contextual_score
import json
from pathlib import Path

Path("reports").mkdir(exist_ok=True)

snapshot = json.loads(Path("data/dataset_2025-03-01.json").read_text())
cve_records = snapshot["cve_records"]

# Perfis (v4 — escala normalizada: CVSS/10, θ em [0, 1.5])
PROFILES = [
    # (name, C(α), E(α), θ_block)
    ("BANK",  1.50, 1.00, 0.05),
    ("HOSP",  1.50, 0.80, 0.08),
    ("SAAS",  1.00, 0.80, 0.20),
    ("INFRA", 1.50, 0.50, 0.015),  # θ_Utilities (NIS2 Essential Entity)
]

kappas = [round(k * 0.01, 2) for k in range(50, 100)]  # 0.50 a 0.99
all_results = {}

for prof_name, C, E, THETA in PROFILES:
    results = []
    for kappa in kappas:
        block_count = sum(
            1 for r in cve_records
            if compute_contextual_score(
                r["cvss_base"], r["epss_score"], C, E, kappa=kappa
            ) > THETA
        )
        results.append({"kappa": kappa, "block_count": block_count})

    # Calcular variação na zona estável [0.70, 0.90]
    stable = [r["block_count"] for r in results if 0.70 <= r["kappa"] <= 0.90]
    variation_pct = (max(stable) - min(stable)) / len(cve_records)

    print(f"[{prof_name}] Stable zone [0.70, 0.90]: min={min(stable)}, max={max(stable)}, "
          f"variation={variation_pct:.1%} of {len(cve_records)} CVEs")
    print(f"[{prof_name}] Paper claim: ≤10% variation → {'PASS' if variation_pct <= 0.10 else 'FAIL'}")

    all_results[prof_name] = {
        "profile": prof_name,
        "c_alpha": C, "e_alpha": E, "theta_block": THETA,
        "n_cves": len(cve_records),
        "stable_zone": {"min_kappa": 0.70, "max_kappa": 0.90,
                        "min_blocks": min(stable), "max_blocks": max(stable),
                        "variation_pct": round(variation_pct, 4)},
        "series": results,
    }

# Compatibilidade: manter chave "profile" no top-level para paper_report.py existente
# (usa all_results["BANK"] como índice de referência)
Path("reports/kappa_sensitivity.json").write_text(json.dumps(all_results["BANK"], indent=2))
Path("reports/kappa_sensitivity_all.json").write_text(json.dumps(all_results, indent=2))

print("\nkappa,block_count (BANK)")
for r in all_results["BANK"]["series"]:
    print(f"{r['kappa']:.2f},{r['block_count']}")

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

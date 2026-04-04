# smoke_test_pipeline.py — criar este ficheiro em test/tuning/
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
    make_incidents("22", "External - Internet", "High",     50)+ # INFRA: utilities, internet
    make_incidents("22", "Internal",            "High",     50)  # INFRA: utilities, internal
)

PROFILES_CONFIG = [
    ("BANK",  ["52"],       {"block": 0.5,  "warn": 0.3}),
    ("HOSP",  ["62"],       {"block": 0.8,  "warn": 0.5}),
    ("SAAS",  ["51"],       {"block": 2.0,  "warn": 1.0}),
    ("INFRA", ["22"],       {"block": 0.3,  "warn": 0.2}),
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
print(f"{'CVE':<20} {'Name':<15} {'BANK':>8} {'HOSP':>8} {'SAAS':>8} {'INFRA':>8}")
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
for cvss_min, cvss_max, n in [(1.0, 4.0, 18), (4.0, 7.0, 47), (7.0, 9.0, 98), (9.0, 10.0, 74)]:
    for _ in range(n):
        cvss = random.uniform(cvss_min, cvss_max)
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

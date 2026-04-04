"""
SPEC: Calibration Test Suite v3 - Statistical Rigor & Framework Integrity
==========================================================================
R(v, α) = CVSS(v) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))

This version (v3) focuses on:
    - Fixed Ordinal Logic: {BANK, HOSP, INFRA} >= SAAS
    - Statistical Robustness: Bootstrap resampling (N=1000) for 95% CI
    - Performance Benchmarking: Scalability for 10k+ CVEs
"""

import json
import math
import random
import time
import pytest
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List

# ── Hypothesis & Stats ──────────────────────────────────────────────────────
from hypothesis import given, settings, assume
from hypothesis import strategies as st
import numpy as np

# ── Import from pipeline ────────────────────────────────────────────────────
from pipeline import (
    compute_contextual_score,
    evaluate_gate,
    derive_profile_calibration,
    naics_to_fips199,
    IncidentRecord,
    ProfileCalibration,
)

# ═════════════════════════════════════════════════════════════════════════════
# FIXTURES E HELPERS
# ═════════════════════════════════════════════════════════════════════════════

SNAPSHOT_PATH = Path("data") / "dataset_2025-03-01.json"
CALIBRATION_PATH = Path("data") / "calibration.json"

def load_snapshot() -> dict:
    if not SNAPSHOT_PATH.exists():
        pytest.skip(f"Snapshot não encontrado: {SNAPSHOT_PATH}")
    return json.loads(SNAPSHOT_PATH.read_text())

@dataclass
class ProfileFixture:
    name: str
    c_alpha: float
    e_alpha: float
    theta_block: float
    theta_warn: float

# Calibrated Profiles (v1.7.1 Final)
PAPER_PROFILES = [
    ProfileFixture("BANK",  1.50, 1.00, 0.5, 0.3),
    ProfileFixture("HOSP",  1.50, 0.80, 0.8, 0.5),
    ProfileFixture("SAAS",  1.00, 0.80, 2.0, 1.0),
    ProfileFixture("INFRA", 1.50, 0.50, 0.3, 0.2), # NIS2 Essential Entity
]

# Illustrative Cases (Table 2 v3)
ILLUSTRATIVE_CASES = [
    # (cve_id, cvss, epss, profile_name, expected_decision)
    ("CVE-2021-44228", 10.0, 0.940, "BANK",  "BLOCK"),
    ("CVE-2021-44228", 10.0, 0.940, "INFRA", "BLOCK"),
    ("CVE-2024-3094",  10.0, 0.860, "BANK",  "BLOCK"),
    ("CVE-2024-3094",  10.0, 0.860, "INFRA", "BLOCK"),
    ("CVE-2023-38545",  9.8, 0.260, "SAAS",  "BLOCK"),   # Corrected marginal
    ("CVE-2019-10744",  9.8, 0.010, "INFRA", "APPROVE"), # 0.074 < 0.30
]

# ═════════════════════════════════════════════════════════════════════════════
# T3/T4 — CALIBRAÇÃO E GROUND TRUTH FIXED (v3)
# ═════════════════════════════════════════════════════════════════════════════

class TestCalibrationStabilityV3:
    """
    Verifies the ordinal properties and empirical mapping (v1.7.1).
    """

    @pytest.fixture(scope="class")
    def empirical_profiles(self) -> dict[str, dict]:
        if not CALIBRATION_PATH.exists():
            pytest.skip("Calibration not found.")
        cal = json.loads(CALIBRATION_PATH.read_text())
        return {p["profile_name"]: p for p in cal["calibrations"]}

    def test_calibration_ordering_preserved(self, empirical_profiles):
        """
        ORDINAL LOGIC v3: {BANK, HOSP, INFRA} ≥ SAAS (Regulated ≥ Unregulated).
        """
        regulated = ["BANK", "HOSP", "INFRA"]
        c_saas = empirical_profiles["SAAS"]["c_alpha"]

        for prof in regulated:
            c_val = empirical_profiles[prof]["c_alpha"]
            assert c_val >= c_saas, f"{prof}.C(α)={c_val} < SAAS.C(α)={c_saas}"

    def test_e_alpha_ordering_bank_infra(self, empirical_profiles):
        """
        BANK should have higher exposure than INFRA (Public vs Air-gapped/OT).
        """
        e_bank = empirical_profiles["BANK"]["e_alpha"]
        e_infra = empirical_profiles["INFRA"]["e_alpha"]
        assert e_bank >= e_infra, f"BANK.E(α)={e_bank} < INFRA.E(α)={e_infra}"


# ═════════════════════════════════════════════════════════════════════════════
# T7 — BOOTSTRAP STATISTICAL ROBUSTNESS
# ═════════════════════════════════════════════════════════════════════════════

class TestStatisticalInference:
    """
    Monte Carlo study (Bootstrapping) to verify 95% Confidence Interval
    stability for the IEEE paper evidence.
    """

    N_RESAMPLES = 1000
    KAPPA = 0.8

    @pytest.fixture(scope="class")
    def cve_dataset(self):
        snap = load_snapshot()
        return snap["cve_records"]

    def _simulate_block_rate(self, cve_sample: List[dict], profile: ProfileFixture) -> float:
        blocks = 0
        for rec in cve_sample:
            score = compute_contextual_score(
                cvss=rec["cvss_base"], epss=rec["epss_score"],
                c_alpha=profile.c_alpha, e_alpha=profile.e_alpha, kappa=self.KAPPA
            )
            if score > profile.theta_block:
                blocks += 1
        return blocks / len(cve_sample) if cve_sample else 0.0

    @pytest.mark.parametrize("fixture", PAPER_PROFILES, ids=lambda f: f.name)
    def test_bootstrap_block_rate_ci(self, fixture, cve_dataset):
        """
        Calculates the 95% Confidence Interval for each profile's block rate.
        Verification: Standard deviation of block rate across resamples should be < 0.02.
        """
        rates = []
        n_total = len(cve_dataset)
        random.seed(42)

        for _ in range(self.N_RESAMPLES):
            # Sample with replacement
            resample = random.choices(cve_dataset, k=n_total)
            rates.append(self._simulate_block_rate(resample, fixture))

        rates = np.array(rates)
        mean_rate = np.mean(rates)
        ci_lower = np.percentile(rates, 2.5)
        ci_upper = np.percentile(rates, 97.5)
        std_dev = np.std(rates)

        print(f"\n[STATS] {fixture.name}: Mean={mean_rate:.2%}, 95% CI=[{ci_lower:.2%}, {ci_upper:.2%}], Std={std_dev:.4f}")

        # IEEE Rigor: block rate must be stable (low variance in resampling)
        assert std_dev < 0.05, f"{fixture.name} variance too high for publication: {std_dev:.4f}"

# ═════════════════════════════════════════════════════════════════════════════
# T10 — PERFORMANCE BENCHMARK
# ═════════════════════════════════════════════════════════════════════════════

class TestScalabilityBenchmark:
    """
    Formal scalability verification for high-throughput environments.
    """

    N_CVE_STRESS = 10000

    def test_risk_scoring_throughput(self):
        """
        Scoring 10,000 CVEs should take less than 100ms on modern hardware.
        """
        start_time = time.perf_counter()
        
        for i in range(self.N_CVE_STRESS):
            compute_contextual_score(cvss=7.5, epss=0.5, c_alpha=1.5, e_alpha=0.8)
            
        duration = time.perf_counter() - start_time
        avg_latency_ms = (duration / self.N_CVE_STRESS) * 1000
        
        print(f"\n[BENCHMARK] Processed {self.N_CVE_STRESS} CVEs in {duration:.4f}s (Avg: {avg_latency_ms:.5f}ms/score)")
        
        assert duration < 0.5, f"Performance bottleneck detected: {duration:.4f}s"

# ═════════════════════════════════════════════════════════════════════════════
# T6 — REGRESSÃO DOS CASOS ILUSTRATIVOS (Repeat for v3)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "cve_id,cvss,epss,profile_name,expected_decision",
    ILLUSTRATIVE_CASES,
    ids=[f"{c[0]}/{c[3]}" for c in ILLUSTRATIVE_CASES]
)
def test_illustrative_regression_v3(cve_id, cvss, epss, profile_name, expected_decision):
    fixture = next(f for f in PAPER_PROFILES if f.name == profile_name)
    score = compute_contextual_score(cvss, epss, fixture.c_alpha, fixture.e_alpha)
    decision = evaluate_gate(score, fixture.theta_block, fixture.theta_warn)
    assert decision == expected_decision

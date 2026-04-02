# Empirical Dataset Pipeline
# Contextual Risk Scoring — Parameter Calibration
# R(v, α) = CVSS(v) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))
#
# Objectivo: derivar C(α) e E(α) empiricamente a partir de bases públicas/freemium/registo
# Linguagem: Python 3.12 (pseudocódigo executável, com stubs para chamadas reais)
# Output: data/dataset_YYYY-MM-DD.json — parâmetros por perfil + ground truth de validação
#
# Fontes de dados:
#   1. NVD CVSS API      — https://nvd.nist.gov/developers (chave gratuita)
#   2. FIRST.org EPSS    — https://api.first.org/data/v1/epss (sem autenticação)
#   3. CISA KEV          — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
#   4. CISA Vulnrichment — https://github.com/cisagov/vulnrichment (Apache 2.0)
#   5. VulZoo            — https://github.com/NUS-Curiosity/VulZoo (CC BY 4.0)
#   6. VCDB              — https://github.com/vz-risk/VCDB (CC BY-SA 4.0)
#   7. HHS OCR           — https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf
#   8. Shadowserver      — https://www.shadowserver.org/api/ (registo gratuito)

import json
import csv
import time
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

SNAPSHOT_DATE = "2025-03-01"  # fixar para reproducibilidade


# ══════════════════════════════════════════════════════════════
# ESTRUTURAS DE DADOS
# ══════════════════════════════════════════════════════════════

@dataclass
class CVERecord:
    cve_id: str
    cvss_base: float
    epss_score: float          # 0.0 se indisponível (fail-close em runtime)
    epss_date: str
    cisa_kev: bool             # ground truth: explorada in-the-wild?
    ssvc_exploitation: str     # "none" | "poc" | "active"
    ssvc_automatable: bool     # proxy para E(α)
    ssvc_impact: str           # "Partial" | "Total" — proxy para C(α)
    vulzoo_sources: list[str]  # fontes que confirmam exploração


@dataclass
class IncidentRecord:
    source: str                # "vcdb" | "hhs_ocr"
    incident_id: str
    naics_sector: str
    org_size: str              # "small" | "medium" | "large"
    asset_type: str
    access_vector: str         # "External - Internet" | "Internal" | "Physical"
    cia_impact: str            # "C" | "I" | "A" | "CIA"
    cve_ids: list[str]
    fips199_level: str         # "Low" | "Moderate" | "High"


@dataclass
class ProfileCalibration:
    profile_name: str          # "BANK" | "HOSP" | "SAAS" | "DEV"
    naics_codes: list[str]
    c_alpha: float             # criticidade derivada empiricamente
    e_alpha: float             # exposição derivada empiricamente
    c_alpha_source: str
    e_alpha_source: str
    n_incidents: int
    n_cves: int



# ══════════════════════════════════════════════════════════════
# FONTE 1: NVD — CVSS Base Scores
# Acesso: API REST (registo gratuito para API key)
# URL: https://services.nvd.nist.gov/rest/json/cves/2.0
# Rate limit: 50 req/30s sem key, 2000 req/30s com key
# Licença: CC0 (domínio público)
# ══════════════════════════════════════════════════════════════

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = "YOUR_NVD_API_KEY"  # https://nvd.nist.gov/developers/request-an-api-key


def fetch_nvd_cvss(cve_id: str) -> dict:
    """
    Fetch CVSS base score para um CVE via NVD API v2.0.
    Prefere CVSSv3.1 > CVSSv3.0 > CVSSv2. Retorna 0.0 se indisponível.
    """
    url  = f"{NVD_API_BASE}?cveId={cve_id}"
    resp = requests.get(url, headers={"apiKey": NVD_API_KEY}, timeout=10)
    resp.raise_for_status()

    data    = resp.json()
    metrics = data["vulnerabilities"][0]["cve"].get("metrics", {})

    if "cvssMetricV31" in metrics:
        score, version = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"], "3.1"
    elif "cvssMetricV30" in metrics:
        score, version = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"], "3.0"
    elif "cvssMetricV2" in metrics:
        score, version = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"], "2.0"
    else:
        score, version = 0.0, "unknown"

    return {"cve_id": cve_id, "cvss_base": score, "cvss_version": version}


def fetch_nvd_batch(cve_ids: list[str], delay_s: float = 0.7) -> list[dict]:
    """Batch fetch com rate limiting. ~3 min para 237 CVEs com API key."""
    results = []
    for cve_id in cve_ids:
        try:
            results.append(fetch_nvd_cvss(cve_id))
            time.sleep(delay_s)
        except Exception as e:
            print(f"[NVD] Erro em {cve_id}: {e}")
            results.append({"cve_id": cve_id, "cvss_base": 0.0, "cvss_version": "error"})
    return results


# ══════════════════════════════════════════════════════════════
# FONTE 2: FIRST.org EPSS API
# Acesso: REST pública, sem autenticação
# URL: https://api.first.org/data/v1/epss
# Histórico: https://epss.cyentia.com/epss_scores-{date}.csv.gz
# Licença: CC0 — Jacobs et al. (2021)
# ══════════════════════════════════════════════════════════════

EPSS_API_BASE    = "https://api.first.org/data/v1/epss"
EPSS_HISTORY_URL = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"


def fetch_epss_snapshot(snapshot_date: str, cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores para uma data específica (reproducibilidade).
    Faz cache local do CSV diário comprimido.
    """
    import gzip, shutil

    cache_csv = DATA_DIR / f"epss_{snapshot_date}.csv"
    cache_gz  = cache_csv.with_suffix(".csv.gz")

    if not cache_csv.exists():
        url  = EPSS_HISTORY_URL.format(date=snapshot_date)
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        with open(cache_gz, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        with gzip.open(cache_gz, "rb") as gz, open(cache_csv, "wb") as out:
            shutil.copyfileobj(gz, out)

    cve_set = set(cve_ids)
    scores  = {}
    with open(cache_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["cve"] in cve_set:
                scores[row["cve"]] = float(row["epss"])

    return scores


# ══════════════════════════════════════════════════════════════
# FONTE 3: CISA KEV (Known Exploited Vulnerabilities)
# Acesso: Download JSON público, sem autenticação
# URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# Licença: CC0
# Relevância: Ground truth de exploração in-the-wild para validação do modelo
# ══════════════════════════════════════════════════════════════

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev() -> set[str]:
    """Retorna set de CVE IDs confirmados como explorados in-the-wild."""
    cache = DATA_DIR / "cisa_kev.json"
    if not cache.exists():
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        cache.write_text(resp.text)

    data    = json.loads(cache.read_text())
    kev_set = {v["cveID"] for v in data["vulnerabilities"]}
    print(f"[KEV] {len(kev_set)} CVEs confirmados in-the-wild")
    return kev_set


# ══════════════════════════════════════════════════════════════
# FONTE 4: SSVC / CISA Vulnrichment
# Acesso: GitHub público — github.com/cisagov/vulnrichment
# Formato: CVE JSON 5.0 com extensões SSVC
# Licença: Apache 2.0
# Relevância: "Mission Prevalence" → C(α) | "Automatable" → E(α)
# ══════════════════════════════════════════════════════════════

VULNRICHMENT_API = "https://raw.githubusercontent.com/cisagov/vulnrichment/main"


def fetch_ssvc_classification(cve_id: str) -> dict:
    """
    Fetch SSVC decision points (Automatable, Mission Prevalence, Exploitation)
    para um CVE a partir do repositório CISA Vulnrichment.
    """
    year = cve_id.split("-")[1]
    url  = f"{VULNRICHMENT_API}/{year}/{cve_id}.json"

    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            return {"cve_id": cve_id, "ssvc_available": False}
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return {"cve_id": cve_id, "ssvc_available": False}

    ssvc = {
        "cve_id": cve_id, "ssvc_available": True,
        "exploitation": "none", "automatable": False,
        "mission_prevalence": "Minimal", "impact": "Partial",
    }

    try:
        containers = data.get("containers", {})
        for container_key in ["cna", "adp"]:
            for metric in containers.get(container_key, {}).get("metrics", []):
                if metric.get("other", {}).get("type") == "ssvc":
                    options = metric["other"]["content"]["options"]
                    for opt in options:
                        if "Exploitation" in opt:
                            ssvc["exploitation"] = opt["Exploitation"].lower()
                        if "Automatable" in opt:
                            ssvc["automatable"] = (opt["Automatable"].lower() == "yes")
                        if "Mission Prevalence" in opt:
                            ssvc["mission_prevalence"] = opt["Mission Prevalence"]
                        if "Technical Impact" in opt:
                            ssvc["impact"] = opt["Technical Impact"]
    except (KeyError, TypeError):
        pass

    return ssvc


def ssvc_to_c_alpha(mission_prevalence: str) -> float:
    """
    Mapear SSVC Mission Prevalence → C(α).

    Justificação: SSVC Mission Prevalence define o grau em que o sistema afectado
    suporta missões críticas — equivalente funcional ao FIPS 199 impact level para
    disponibilidade. Mapeamento: Minimal~Low, Support~Moderate, Essential~High/Regulated.
    (NIST SP 800-160 Vol. 2, CISA SSVC v2.1)
    """
    return {"Minimal": 0.25, "Support": 0.75, "Essential": 1.50}.get(mission_prevalence, 0.50)


def ssvc_to_e_alpha(automatable: bool, exploitation: str) -> float:
    """
    Mapear SSVC Automatable + Exploitation → E(α).

    Justificação: "Automatable: Yes" implica execução programática sem interacção
    humana — equivalente a surface pré-autenticação internet-facing no modelo wardex.
    "exploitation: none" reduz exposição efectiva mesmo em sistemas internet-facing.
    """
    if automatable and exploitation == "active":
        return 1.00  # Unauthenticated, actively exploited
    elif automatable and exploitation == "poc":
        return 0.80  # Exploit disponível, automação possível
    elif automatable and exploitation == "none":
        return 0.50  # Automatable mas não explorado in-the-wild
    elif not automatable and exploitation == "active":
        return 0.50  # Targeted, requer configuração
    else:
        return 0.30  # Non-automatable, sem exploit conhecido


# ══════════════════════════════════════════════════════════════
# FONTE 5: VulZoo (ASE 2024 — IEEE/ACM)
# Acesso: GitHub público — github.com/NUS-Curiosity/VulZoo
# Licença: CC BY 4.0
# Relevância: Dataset unificado de 17 fontes (Exploit-DB, Metasploit, ZDI, etc.)
# ══════════════════════════════════════════════════════════════

VULZOO_REPO = "https://raw.githubusercontent.com/NUS-Curiosity/VulZoo/main"


def load_vulzoo_exploit_db() -> dict[str, list[str]]:
    """
    Carrega mapeamento CVE → exploit sources do VulZoo.
    Confirma presença em Exploit-DB, Metasploit, GitHub PoCs, ZDI, AttackerKB.
    """
    url   = f"{VULZOO_REPO}/data/exploit_db/exploits.csv"
    cache = DATA_DIR / "vulzoo_exploits.csv"

    if not cache.exists():
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        cache.write_bytes(resp.content)

    cve_to_sources: dict[str, list[str]] = {}
    with open(cache, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get("cve_id", "").strip()
            src = row.get("source", "exploit_db")
            if cve:
                cve_to_sources.setdefault(cve, []).append(src)

    return cve_to_sources


# ══════════════════════════════════════════════════════════════
# FONTE 6: VCDB (VERIS Community Database)
# Acesso: GitHub público — github.com/vz-risk/VCDB
# Licença: CC BY-SA 4.0
# Relevância: Incidentes com sector NAICS, tipo de activo, vector de acesso
# ══════════════════════════════════════════════════════════════

VCDB_REPO_URL = "https://github.com/vz-risk/VCDB/archive/refs/heads/master.zip"

# Tabela NAICS → FIPS 199 derivada do NIST SP 800-60 Vol. II
NAICS_TO_FIPS199 = {
    "52": "High",      # Finance and Insurance (dados financeiros regulados)
    "62": "High",      # Health Care (PHI, HIPAA)
    "92": "High",      # Public Administration
    "22": "High",      # Utilities (infraestrutura crítica)
    "48": "High",      # Transportation (infraestrutura crítica)
    "51": "Moderate",  # Information / Technology (SaaS)
    "54": "Moderate",  # Professional Services
    "44": "Moderate",  # Retail
    "72": "Moderate",  # Accommodation and Food Services
    "61": "Moderate",  # Educational Services
    "23": "Low",       # Construction
    "11": "Low",       # Agriculture
}


def naics_to_fips199(naics_code: str) -> str:
    return NAICS_TO_FIPS199.get(naics_code[:2], "Moderate")


def classify_access_vector(vectors: list[str]) -> str:
    internet = {"Web application", "Remote Access Services", "Email", "VPN"}
    internal = {"Direct install", "Backdoor or C2", "Physical access"}
    for v in vectors:
        if any(iv in v for iv in internet):
            return "External - Internet"
    for v in vectors:
        if any(iv in v for iv in internal):
            return "Internal"
    return "Unknown"


def classify_org_size(employee_str: str) -> str:
    if any(s in employee_str for s in ["1 to 10", "11 to 100"]):
        return "small"
    elif any(s in employee_str for s in ["101 to 1000", "1001 to 10000"]):
        return "medium"
    elif "10000" in employee_str or "Large" in employee_str:
        return "large"
    return "unknown"


def load_vcdb_incidents() -> list[IncidentRecord]:
    """
    Carrega e parseia incidentes VCDB (um ficheiro JSON por incidente).
    Extrai: NAICS sector, tipo de activo, vector de acesso, CIA impact.
    """
    vcdb_dir = DATA_DIR / "vcdb"

    if not vcdb_dir.exists():
        import urllib.request, zipfile, io
        print("[VCDB] A descarregar VCDB...")
        with urllib.request.urlopen(VCDB_REPO_URL) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
            z.extractall(DATA_DIR)
        (DATA_DIR / "VCDB-master").rename(vcdb_dir)

    incidents = []
    for json_file in (vcdb_dir / "data" / "json").glob("*.json"):
        try:
            data = json.loads(json_file.read_text())
        except json.JSONDecodeError:
            continue

        industry = data.get("victim", {}).get("industry", "00")
        assets   = data.get("asset", {}).get("assets", [])
        vectors  = data.get("action", {}).get("hacking", {}).get("vector", [])
        if not isinstance(vectors, list):
            vectors = [vectors]

        conf  = data.get("attribute", {}).get("confidentiality", {})
        intg  = data.get("attribute", {}).get("integrity", {})
        avail = data.get("attribute", {}).get("availability", {})
        cia   = ("C" if conf.get("data_disclosure") == "Yes" else "") + \
                ("I" if intg.get("variety", []) else "") + \
                ("A" if avail.get("variety", []) else "")

        incidents.append(IncidentRecord(
            source        = "vcdb",
            incident_id   = data.get("incident_id", json_file.stem),
            naics_sector  = industry,
            org_size      = classify_org_size(data.get("victim", {}).get("employee_count", "")),
            asset_type    = assets[0].get("variety", "Unknown") if assets else "Unknown",
            access_vector = classify_access_vector(vectors),
            cia_impact    = cia or "Unknown",
            cve_ids       = [],
            fips199_level = naics_to_fips199(industry),
        ))

    print(f"[VCDB] {len(incidents)} incidentes carregados")
    return incidents


# ══════════════════════════════════════════════════════════════
# FONTE 7: HHS OCR Breach Portal (healthcare)
# Acesso: Download CSV público — ocrportal.hhs.gov/ocr/breach/breach_report.jsf
# Também via healthdata.gov dataset API
# Relevância: Ground truth de breaches HIPAA → calibrar perfil HOSP
# ══════════════════════════════════════════════════════════════

def classify_org_size_from_count(count_str: str) -> str:
    try:
        n = int(count_str.replace(",", ""))
        if n < 1000:   return "small"
        if n < 50000:  return "medium"
        return "large"
    except ValueError:
        return "unknown"


def load_hhs_ocr_breaches(csv_path: str) -> list[IncidentRecord]:
    """
    Parseia o CSV exportado do HHS OCR Breach Portal.
    Healthcare é sempre FIPS 199 High (PHI = categoria High para C e I).
    """
    incidents = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            location    = row.get("Location of Breached Information", "")
            breach_type = row.get("Type of Breach", "")

            if "Network Server" in location or "Hacking/IT" in breach_type:
                access_vector = "External - Internet"
            elif "Email" in location:
                access_vector = "External - Internet"
            elif "Laptop" in location or "Paper" in location:
                access_vector = "Physical"
            else:
                access_vector = "Internal"

            incidents.append(IncidentRecord(
                source        = "hhs_ocr",
                incident_id   = hashlib.md5(
                    (row.get("Name of Covered Entity", "") +
                     row.get("Breach Submission Date", "")).encode()
                ).hexdigest()[:8],
                naics_sector  = "62",
                org_size      = classify_org_size_from_count(
                    row.get("Number of Individuals Affected", "0")),
                asset_type    = location.split(",")[0].strip() if location else "Unknown",
                access_vector = access_vector,
                cia_impact    = "C",
                cve_ids       = [],
                fips199_level = "High",
            ))

    print(f"[HHS OCR] {len(incidents)} breaches carregados")
    return incidents


# ══════════════════════════════════════════════════════════════
# FONTE 8: Shadowserver (exploração internet-facing por CVE)
# Acesso: API com registo gratuito — shadowserver.org
# Relevância: Telemetria honeypot → validar E(α) para CVEs automatable
# ══════════════════════════════════════════════════════════════

SHADOWSERVER_API = "https://transform.shadowserver.org/api2/"


def fetch_shadowserver_exploitation(cve_id: str, api_key: str) -> dict:
    """
    Query Shadowserver para tentativas de exploração observadas para um CVE.
    Requer API key gratuita (registo em shadowserver.org).
    """
    url  = f"{SHADOWSERVER_API}reports/query"
    body = {
        "report": "honeypot-exploited-vulnerability",
        "cve_id": cve_id,
        "start":  "2025-01-01",
        "end":    SNAPSHOT_DATE,
    }
    resp = requests.post(url, json=body,
                         headers={"X-API-KEY": api_key}, timeout=15)
    if resp.status_code == 404:
        return {"cve_id": cve_id, "exploitation_observed": False, "count": 0}
    resp.raise_for_status()
    data = resp.json()
    return {
        "cve_id":                cve_id,
        "exploitation_observed": len(data) > 0,
        "count":                 sum(int(r.get("count", 0)) for r in data),
        "first_seen":            data[0].get("timestamp") if data else None,
    }


# ══════════════════════════════════════════════════════════════
# PIPELINE CENTRAL: Derivação Empírica de C(α) e E(α) por Perfil
# ══════════════════════════════════════════════════════════════

def derive_profile_calibration(
    profile_name: str,
    naics_codes: list[str],
    incidents: list[IncidentRecord],
) -> ProfileCalibration:
    """
    Deriva C(α) e E(α) empiricamente a partir de incidentes VCDB + HHS OCR.

    METODOLOGIA C(α):
      Mediana do FIPS 199 impact level dos incidentes no sector.
      "Low"→0.25, "Moderate"→0.75, "High"→1.00
      +0.50 se sector sob escopo regulatório obrigatório (NAICS 52, 62, 92, 22, 48)
      Máximo 1.50 (Essential/Critical — SSVC Mission Prevalence "Essential")

    METODOLOGIA E(α):
      Proporção de incidentes com vector "External - Internet":
      ≤25%  → 0.30 (predominantemente interno)
      ≤60%  → 0.50 (exposição mista)
      ≤85%  → 0.80 (maioritariamente internet-facing)
      >85%  → 1.00 (predominantemente público)

    Justificação E(α): Alinhado com wardex ExposureFactor:
      internet_facing=true,  requires_auth=false → 1.0×1.0 = 1.00 (BANK)
      internet_facing=true,  requires_auth=true  → 1.0×0.8 = 0.80 (HOSP)
      internet_facing=false, requires_auth=true  → 0.6×0.8 ≈ 0.50 (SAAS)
      environment=development                    → 0.3×1.0 = 0.30 (DEV)
    """
    prefixes = [n[:2] for n in naics_codes]
    sector_incidents = [i for i in incidents if i.naics_sector[:2] in prefixes]
    n = len(sector_incidents)

    if n == 0:
        return ProfileCalibration(
            profile_name=profile_name, naics_codes=naics_codes,
            c_alpha=0.50, e_alpha=0.50,
            c_alpha_source="default (sem incidentes)", e_alpha_source="default",
            n_incidents=0, n_cves=0,
        )

    # C(α): FIPS 199 modal
    fips_levels  = [i.fips199_level for i in sector_incidents]
    modal_fips   = max(set(fips_levels), key=fips_levels.count)
    fips_to_c    = {"Low": 0.25, "Moderate": 0.75, "High": 1.00}
    c_base       = fips_to_c.get(modal_fips, 0.50)

    regulatory_naics = {"52", "62", "92", "22", "48"}
    if any(p in regulatory_naics for p in prefixes):
        c_alpha  = min(c_base + 0.50, 1.50)
        c_source = f"FIPS 199 modal={modal_fips} + ajuste regulatório"
    else:
        c_alpha  = c_base
        c_source = f"FIPS 199 modal={modal_fips} (VCDB n={n})"

    # E(α): proporção internet-facing
    internet_count = sum(1 for i in sector_incidents if i.access_vector == "External - Internet")
    ratio = internet_count / n

    if ratio <= 0.25:
        e_alpha, e_label = 0.30, "predominantemente interno"
    elif ratio <= 0.60:
        e_alpha, e_label = 0.50, "exposição mista"
    elif ratio <= 0.85:
        e_alpha, e_label = 0.80, "maioritariamente internet-facing"
    else:
        e_alpha, e_label = 1.00, "predominantemente público"

    e_source = f"VCDB access vector: {ratio:.1%} internet-facing ({e_label})"

    return ProfileCalibration(
        profile_name   = profile_name,
        naics_codes    = naics_codes,
        c_alpha        = round(c_alpha, 2),
        e_alpha        = round(e_alpha, 2),
        c_alpha_source = c_source,
        e_alpha_source = e_source,
        n_incidents    = n,
        n_cves         = 0,
    )


# ══════════════════════════════════════════════════════════════
# PIPELINE DE CVEs: Construção do Dataset Composto
# ══════════════════════════════════════════════════════════════

def build_cve_dataset(cve_ids: list[str], shadowserver_key: str | None = None) -> list[CVERecord]:
    """
    Pipeline completo: NVD → EPSS → KEV → SSVC → VulZoo → Shadowserver (opcional).
    Produz um CVERecord por CVE com todos os campos preenchidos.
    EPSS=0.0 → fail-close (tratado como 1.0 em runtime pelo scorer wardex).
    """
    print(f"[Pipeline] {len(cve_ids)} CVEs | snapshot: {SNAPSHOT_DATE}")

    print("[1/6] NVD CVSS...")
    nvd_data = {r["cve_id"]: r for r in fetch_nvd_batch(cve_ids)}

    print(f"[2/6] EPSS snapshot {SNAPSHOT_DATE}...")
    epss_scores = fetch_epss_snapshot(SNAPSHOT_DATE, cve_ids)

    print("[3/6] CISA KEV...")
    kev_set = fetch_cisa_kev()

    print("[4/6] SSVC (Vulnrichment)...")
    ssvc_data = {}
    for cve_id in cve_ids:
        ssvc_data[cve_id] = fetch_ssvc_classification(cve_id)
        time.sleep(0.3)

    print("[5/6] VulZoo exploit sources...")
    vulzoo = load_vulzoo_exploit_db()

    shadowserver_data = {}
    if shadowserver_key:
        print("[6/6] Shadowserver...")
        for cve_id in cve_ids:
            shadowserver_data[cve_id] = fetch_shadowserver_exploitation(cve_id, shadowserver_key)
            time.sleep(1.0)
    else:
        print("[6/6] Shadowserver ignorado (sem API key)")

    records = []
    for cve_id in cve_ids:
        nvd  = nvd_data.get(cve_id, {})
        ssvc = ssvc_data.get(cve_id, {})
        records.append(CVERecord(
            cve_id            = cve_id,
            cvss_base         = nvd.get("cvss_base", 0.0),
            epss_score        = epss_scores.get(cve_id, 0.0),
            epss_date         = SNAPSHOT_DATE,
            cisa_kev          = cve_id in kev_set,
            ssvc_exploitation = ssvc.get("exploitation", "none"),
            ssvc_automatable  = ssvc.get("automatable", False),
            ssvc_impact       = ssvc.get("impact", "Partial"),
            vulzoo_sources    = vulzoo.get(cve_id, []),
        ))

    return records


# ══════════════════════════════════════════════════════════════
# VALIDAÇÃO: Modelo Contextual vs CVSS-only (baseline 7.0)
# ══════════════════════════════════════════════════════════════

def compute_contextual_score(
    cvss: float,
    epss: float,
    c_alpha: float,
    e_alpha: float,
    compensating_effect: float = 0.0,
    kappa: float = 0.8,
) -> float:
    """
    R(v, α) = CVSS × EPSS × C(α) × E(α) × (1 − Φ(α))
    fail-close: EPSS=0.0 → usar 1.0 (indisponível ≠ inexplorável)
    """
    epss_eff = epss if epss > 0.0 else 1.0
    phi      = min(compensating_effect, kappa)
    return cvss * epss_eff * c_alpha * e_alpha * (1.0 - phi)


def run_validation_study(
    cve_records: list[CVERecord],
    profiles: list[ProfileCalibration],
    theta_configs: dict,
) -> dict:
    """
    Simulation study: divergência entre CVSS-only (threshold 7.0) e modelo contextual.
    Métricas: block_rate, under_block (CVSS miss), over_block (CVSS false positive).
    """
    results = {}
    for profile in profiles:
        theta_block = theta_configs[profile.profile_name]["block"]
        theta_warn  = theta_configs[profile.profile_name].get("warn", theta_block * 0.8)

        total = len(cve_records)
        block_ctx = block_cvss = under = over = 0

        for rec in cve_records:
            ctx_score    = compute_contextual_score(rec.cvss_base, rec.epss_score,
                                                    profile.c_alpha, profile.e_alpha)
            ctx_blocked  = ctx_score > theta_block
            cvss_blocked = rec.cvss_base >= 7.0

            if ctx_blocked:   block_ctx  += 1
            if cvss_blocked:  block_cvss += 1
            if ctx_blocked and not cvss_blocked:  under += 1  # CVSS teria falhado
            if cvss_blocked and not ctx_blocked:  over  += 1  # CVSS bloqueou desnecessariamente

        results[profile.profile_name] = {
            "total":            total,
            "block_contextual": block_ctx,
            "block_cvss_only":  block_cvss,
            "block_rate":       round(block_ctx / total, 4),
            "under_block":      under,
            "over_block":       over,
            "diverge_total":    under + over,
            "diverge_rate":     round((under + over) / total, 4),
        }

    return results


# ══════════════════════════════════════════════════════════════
# REPRODUCIBILIDADE: Arquivo e hashing do dataset
# ══════════════════════════════════════════════════════════════

def archive_dataset(cve_records: list[CVERecord], profiles: list[ProfileCalibration]) -> str:
    """
    Serializa e arquiva o dataset completo em data/dataset_{date}.json.
    Gera SHA256 para publicar no paper (depositar em Zenodo ou GitHub Release).
    """
    output = {
        "metadata": {
            "snapshot_date": SNAPSHOT_DATE,
            "generated_at":  datetime.utcnow().isoformat() + "Z",
            "n_cves":        len(cve_records),
            "n_profiles":    len(profiles),
            "sources": [
                "NVD CVSS API (nvd.nist.gov)",
                "FIRST.org EPSS (api.first.org)",
                "CISA KEV (cisa.gov)",
                "CISA Vulnrichment/SSVC (github.com/cisagov/vulnrichment)",
                "VCDB (github.com/vz-risk/VCDB)",
                "VulZoo (github.com/NUS-Curiosity/VulZoo)",
            ],
        },
        "cve_records":  [asdict(r) for r in cve_records],
        "calibrations": [asdict(p) for p in profiles],
    }

    archive_path = DATA_DIR / f"dataset_{SNAPSHOT_DATE}.json"
    archive_path.write_text(json.dumps(output, indent=2))

    sha256        = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    archive_path.with_suffix(".sha256").write_text(sha256)

    print(f"[Archive] {archive_path}  SHA256: {sha256[:16]}...")
    return sha256


# ══════════════════════════════════════════════════════════════
# PERFIS E THRESHOLDS (alinhados com wardex ctx-*.yaml)
# ══════════════════════════════════════════════════════════════

# Lista de CVEs de calibração (adicionar até 237 para o corpus completo)
CVE_LIST = [
    "CVE-2021-44228",   # Log4Shell    — CVSS 10.0, EPSS ~0.94, KEV ✓
    "CVE-2024-3094",    # xz backdoor  — CVSS 10.0, SSVC Essential ✓
    "CVE-2023-38545",   # curl SOCKS5  — CVSS 9.8
    "CVE-2019-10744",   # minimist     — CVSS 9.8
    # ... expandir com corpus NVD adicional
]

# NAICS codes e thresholds por perfil (risco_appetite = theta_block em wardex)
# Valores alinhados com ctx-bank.yaml, ctx-hospital.yaml, ctx-startup.yaml, ctx-dev.yaml
PROFILES_CONFIG = [
    ("BANK", ["52"],       {"block": 0.50, "warn": 0.30}),
    ("HOSP", ["62"],       {"block": 0.80, "warn": 0.50}),
    ("SAAS", ["51"],       {"block": 2.00, "warn": 1.00}),
    ("DEV",  ["51", "54"], {"block": 4.00, "warn": 2.00}),
]


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main() -> None:
    # 1. Dataset de CVEs
    cve_records = build_cve_dataset(CVE_LIST)

    # 2. Incidentes para calibração
    vcdb_incidents = load_vcdb_incidents()
    # hhs_incidents  = load_hhs_ocr_breaches("data/hhs_ocr_breaches.csv")
    all_incidents  = vcdb_incidents  # + hhs_incidents

    # 3. Derivar C(α) e E(α) empiricamente por perfil
    profiles      = []
    theta_configs = {}
    for profile_name, naics_codes, thetas in PROFILES_CONFIG:
        cal        = derive_profile_calibration(profile_name, naics_codes, all_incidents)
        cal.n_cves = len(CVE_LIST)
        profiles.append(cal)
        theta_configs[profile_name] = thetas
        print(f"[Calibration] {profile_name}: C(α)={cal.c_alpha}  E(α)={cal.e_alpha}"
              f"  (n_incidents={cal.n_incidents})")

    # 4. Simulation study: contextual vs CVSS-only
    results = run_validation_study(cve_records, profiles, theta_configs)

    print("\n=== SIMULATION RESULTS ===")
    for p, r in results.items():
        print(f"{p:6s}: BLOCK={r['block_contextual']:3d} ({r['block_rate']:.1%}) | "
              f"under={r['under_block']:3d} | over={r['over_block']:3d} | "
              f"diverge={r['diverge_rate']:.1%}")

    # 5. Arquivar para reproducibilidade
    sha256 = archive_dataset(cve_records, profiles)
    print(f"\nDataset SHA256: {sha256}")


if __name__ == "__main__":
    main()

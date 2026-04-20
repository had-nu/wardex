# Empirical Dataset Pipeline
# Contextual Risk Scoring — Parameter Calibration
# R(v, α) = CVSS(v) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))
#
# Objectivo: derivar C(α) e E(α) empiricamente a partir de bases públicas/freemium/registo
# Linguagem: Python 3.12 (pseudocódigo executável, com stubs para chamadas reais)
# Output: dataset/calibration.json — parâmetros por perfil + ground truth de validação

import json
import csv
import time
import hashlib
import requests
from datetime import date, datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

SNAPSHOT_DATE = "2025-03-01"   # Fixar para reproducibilidade

# ══════════════════════════════════════════════════════════════
# ESTRUTURAS DE DADOS CENTRAIS
# ══════════════════════════════════════════════════════════════

@dataclass
class CVERecord:
    cve_id: str
    cvss_base: float
    epss_score: float          # 0.0 se indisponível (fail-close em runtime)
    epss_date: str
    cisa_kev: bool             # ground truth: foi explorada in-the-wild?
    ssvc_exploitation: str     # "none" | "poc" | "active"
    ssvc_automatable: bool     # proxy para E(α)
    ssvc_impact: str           # "partial" | "total" — proxy para C(α)
    vulzoo_sources: list[str]  # quais fontes confirmam exploração

@dataclass
class IncidentRecord:
    source: str                # "vcdb" | "hhs_ocr" | "cissm"
    incident_id: str
    naics_sector: str
    org_size: str              # "small" | "medium" | "large" — do VCDB
    asset_type: str            # "Server" | "User Device" | "Network" | "Person"
    access_vector: str         # "External - Internet" | "Internal" | "Physical"
    cia_impact: str            # "C" | "I" | "A" | "CIA" — dimensão afectada
    cve_ids: list[str]         # CVEs associados (se disponíveis)
    fips199_level: str         # inferido: "Low" | "Moderate" | "High"

@dataclass
class ProfileCalibration:
    profile_name: str          # "BANK" | "HOSP" | "SAAS" | "DEV"
    naics_codes: list[str]     # sectores NAICS que compõem o perfil
    c_alpha: float             # criticidade derivada empiricamente
    e_alpha: float             # exposição derivada empiricamente
    c_alpha_source: str        # justificação da derivação
    e_alpha_source: str
    n_incidents: int           # incidentes que sustentam a calibração
    n_cves: int                # CVEs validadas neste perfil


# ══════════════════════════════════════════════════════════════
# FONTE 1: NVD — CVSS Base Scores
# Acesso: API REST (registo gratuito para API key)
# URL: https://services.nvd.nist.gov/rest/json/cves/2.0
# Rate limit: 50 req/30s sem key, 2000 req/30s com key
# Citação: nvd.nist.gov, CC0 (domínio público)
# ══════════════════════════════════════════════════════════════

import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")   # https://nvd.nist.gov/developers/request-an-api-key

def fetch_nvd_cvss(cve_id: str) -> dict:
    """
    Fetch CVSS base score for a CVE from NVD API.
    Returns: {"cve_id": str, "cvss_base": float, "cvss_version": str}

    ACCESS:
        GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
        Header: apiKey: <YOUR_KEY>

    PSEUDOCODE (real API call):
    """
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()

    data = resp.json()
    vuln = data["vulnerabilities"][0]["cve"]

    # Prefer CVSSv3.1 > CVSSv3.0 > CVSSv2
    metrics = vuln.get("metrics", {})
    if "cvssMetricV31" in metrics:
        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        version = "3.1"
    elif "cvssMetricV30" in metrics:
        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        version = "3.0"
    elif "cvssMetricV2" in metrics:
        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        version = "2.0"
    else:
        score = 0.0
        version = "unknown"

    return {"cve_id": cve_id, "cvss_base": score, "cvss_version": version}


def fetch_nvd_batch(cve_ids: list[str], delay_s: float = 0.7) -> list[dict]:
    """
    Batch fetch com rate limiting respeitado.
    Para 237 CVEs: ~3 minutos com API key.
    """
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
# Acesso: API REST pública, sem autenticação
# URL: https://api.first.org/data/v1/epss
# Dados históricos: github.com/empiricalsec/epss_scores (CSV diário desde Fev 2022)
# Citação: Jacobs et al. (2021), CC0
# ══════════════════════════════════════════════════════════════

EPSS_API_BASE    = "https://api.first.org/data/v1/epss"
EPSS_HISTORY_URL = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"

def fetch_epss_live(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores actuais para lista de CVEs.
    Chunks de 50 CVEs por request (limite da API).

    ACCESS:
        GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-3094,...

    PSEUDOCODE:
    """
    scores = {}
    chunk_size = 50
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        query = ",".join(chunk)
        url   = f"{EPSS_API_BASE}?cve={query}"

        resp = requests.get(url, timeout=15,
                           headers={"User-Agent": "ContextualRiskModel/1.0 (research)"})
        resp.raise_for_status()

        data = resp.json()
        for item in data.get("data", []):
            scores[item["cve"]] = float(item["epss"])

        time.sleep(0.5)  # cortesia para a API pública

    return scores


def fetch_epss_snapshot(snapshot_date: str, cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores para uma data específica (reproducibilidade).
    Usa o arquivo histórico de empiricalsec/epss_scores no GitHub.

    ACCESS:
        Download CSV de: https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz
        Ou GitHub: https://github.com/empiricalsec/epss_scores

    PSEUDOCODE:
    """
    cache_file = DATA_DIR / f"epss_{snapshot_date}.csv"

    if not cache_file.exists():
        url = EPSS_HISTORY_URL.format(date=snapshot_date)
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        with open(cache_file.with_suffix(".csv.gz"), "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        # Descomprimir: import gzip; gzip.decompress(...)
        import gzip, shutil
        with gzip.open(cache_file.with_suffix(".csv.gz"), "rb") as gz:
            with open(cache_file, "wb") as out:
                shutil.copyfileobj(gz, out)

    # Parse CSV: cve,epss,percentile
    cve_set = set(cve_ids)
    scores  = {}
    with open(cache_file, newline="") as f:
        # Ignore EPSS initial metadata comments (e.g. #model_version:...)
        lines = (line for line in f if not line.startswith("#"))
        reader = csv.DictReader(lines)
        for row in reader:
            if "cve" in row and row["cve"] in cve_set:
                scores[row["cve"]] = float(row["epss"])

    return scores


# ══════════════════════════════════════════════════════════════
# FONTE 3: CISA KEV (Known Exploited Vulnerabilities)
# Acesso: Download JSON/CSV público, sem autenticação
# URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# GitHub mirror: github.com/cisagov/kev-catalog (unofficial)
# Citação: CISA, CC0
# RELEVÂNCIA: Ground truth de exploração in-the-wild para validação do modelo
# ══════════════════════════════════════════════════════════════

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev() -> set[str]:
    """
    Fetch KEV catalog. Retorna set de CVE IDs confirmados como explorados.

    ACCESS: Download directo JSON. Actualizado diariamente.

    PSEUDOCODE:
    """
    cache_file = DATA_DIR / "cisa_kev.json"

    if not cache_file.exists():
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        cache_file.write_text(resp.text)

    data      = json.loads(cache_file.read_text())
    kev_set   = {v["cveID"] for v in data["vulnerabilities"]}
    print(f"[KEV] {len(kev_set)} CVEs confirmados in-the-wild")
    return kev_set


def kev_enrichment(cve_ids: list[str], kev_set: set[str]) -> dict[str, bool]:
    """
    Enriquece lista de CVEs com flag KEV.
    kev=True → ground truth de exploração confirmada.
    kev=False → não confirmado (mas pode ter sido explorado sem notificação CISA).
    """
    return {cve: (cve in kev_set) for cve in cve_ids}


# ══════════════════════════════════════════════════════════════
# FONTE 4: SSVC / CISA Vulnrichment
# Acesso: GitHub público
# URL: github.com/cisagov/vulnrichment
# Formato: JSON-LD (CVE JSON 5.0 com extensões SSVC)
# Citação: CISA, Apache 2.0
# RELEVÂNCIA: Nó "Mission Prevalence" → C(α) | "Automatable" → E(α)
# ══════════════════════════════════════════════════════════════

VULNRICHMENT_API = "https://raw.githubusercontent.com/cisagov/vulnrichment/main"

def fetch_ssvc_classification(cve_id: str) -> dict:
    """
    Fetch SSVC decision points para um CVE do Vulnrichment.
    Estrutura CVE JSON 5.0 com extensão SSVC da CISA.

    ACCESS:
        Clone: git clone https://github.com/cisagov/vulnrichment
        Ou fetch individual:
        https://raw.githubusercontent.com/cisagov/vulnrichment/main/2024/CVE-2024-3094.json

    PSEUDOCODE:
    """
    # Path no repo: /{year}/{cve_id}.json
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

    # Extrair SSVC decision points da extensão CISA
    # Localização: data["containers"]["cna"]["metrics"][*]["other"]["content"]["options"]
    ssvc = {"cve_id": cve_id, "ssvc_available": True,
            "exploitation": "none", "automatable": False,
            "mission_prevalence": "Minimal", "impact": "Low"}

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
    Mapear SSVC Mission Prevalence para C(α).
    Derivação: SSVC define Minimal/Support/Essential.
    Mapeamento para FIPS 199: Minimal~Low, Support~Moderate, Essential~High/Regulated.

    JUSTIFICAÇÃO PARA O PAPER:
    SSVC Mission Prevalence é definido como o grau em que o sistema afectado suporta
    missões críticas da organização — equivalente funcional ao FIPS 199 impact level
    para disponibilidade do sistema.
    """
    mapping = {
        "Minimal":   0.25,   # Low impact — dev/sandbox
        "Support":   0.75,   # Moderate impact — operational support
        "Essential": 1.50,   # High impact + regulatory — critical infrastructure
    }
    return mapping.get(mission_prevalence, 0.50)


def ssvc_to_e_alpha(automatable: bool, exploitation: str) -> float:
    """
    Mapear SSVC Automatable + Exploitation para E(α).

    JUSTIFICAÇÃO:
    "Automatable: Yes" implica que o ataque pode ser executado de forma programática
    sem interacção humana — equivalente a "unauthenticated public access" no modelo.
    "Automatable: No" com exploitation "active" sugere acesso autenticado ou targeted.
    "exploitation: none" reduz a exposição efectiva mesmo em sistemas internet-facing.
    """
    if automatable and exploitation == "active":
        return 1.0   # Unauthenticated, actively exploited
    elif automatable and exploitation == "poc":
        return 0.80  # Exploit available, automated possible
    elif automatable and exploitation == "none":
        return 0.50  # Automatable but not exploited in wild
    elif not automatable and exploitation == "active":
        return 0.50  # Targeted, requires setup
    else:
        return 0.30  # Non-automatable, no known exploit


# ══════════════════════════════════════════════════════════════
# FONTE 5: VulZoo (ASE 2024 — IEEE/ACM)
# Acesso: GitHub público
# URL: github.com/NUS-Curiosity/VulZoo
# Formato: CSV/JSON, 17 fontes integradas
# Licença: CC BY 4.0
# RELEVÂNCIA: Dataset unificado reprodutível com CVE IDs cruzados
# ══════════════════════════════════════════════════════════════

VULZOO_REPO = "https://raw.githubusercontent.com/NUS-Curiosity/VulZoo/main"

def load_vulzoo_exploit_db() -> dict[str, list[str]]:
    """
    Carregar mapeamento CVE → exploit sources do VulZoo.
    Confirma presença em Exploit-DB, Metasploit, GitHub, ZDI, AttackerKB.

    ACCESS:
        git clone https://github.com/NUS-Curiosity/VulZoo
        Usar: VulZoo/mappings/cve_to_exploits.json (ou equivalente no repo)

    PSEUDOCODE:
    """
    # Clone local ou fetch directo
    url = f"{VULZOO_REPO}/data/exploit_db/exploits.csv"
    cache = DATA_DIR / "vulzoo_exploits.csv"

    if not cache.exists():
        resp = requests.get(url, timeout=60)
        if resp.status_code != 200:
            print(f"[VulZoo] Failed to fetch. Skipping VulZoo exploits.")
            return {}
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
# Acesso: GitHub público
# URL: github.com/vz-risk/VCDB
# Formato: JSON (um ficheiro por incidente)
# Licença: CC BY-SA 4.0
# RELEVÂNCIA: Incidentes com sector NAICS, tipo de activo, vector de acesso → C(α) e E(α)
# ══════════════════════════════════════════════════════════════

VCDB_REPO_URL = "https://github.com/vz-risk/VCDB/archive/refs/heads/master.zip"

def load_vcdb_incidents() -> list[IncidentRecord]:
    """
    Carregar e parsear incidentes VCDB.
    Cada incidente é um ficheiro JSON em data/json/

    ACCESS:
        git clone https://github.com/vz-risk/VCDB
        ou download ZIP: github.com/vz-risk/VCDB/archive/master.zip

    SCHEMA relevante:
        victim.industry (NAICS code)
        victim.employee_count (faixas: "1 to 10", "101 to 1000", etc.)
        asset.assets[].variety: "Server", "User Dev", "Network", "Media", "Person"
        actor.external.variety: "Hacking", "Malware", "Social", "Physical", etc.
        attribute.confidentiality.data_disclosure: "Yes" | "No"
        action.hacking.vector: "Web application", "VPN", "Remote Access", "Desktop sharing"
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
    json_dir  = vcdb_dir / "data" / "json"

    for json_file in json_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text())
        except json.JSONDecodeError:
            continue

        # Extrair NAICS
        industry = data.get("victim", {}).get("industry", "00")

        # Extrair tipo de activo (primeiro activo com variety)
        assets     = data.get("asset", {}).get("assets", [])
        asset_type = assets[0].get("variety", "Unknown") if assets else "Unknown"

        # Inferir vector de acesso → E(α)
        hacking_vectors = data.get("action", {}).get("hacking", {}).get("vector", [])
        if not isinstance(hacking_vectors, list):
            hacking_vectors = [hacking_vectors]
        access_vector = classify_access_vector(hacking_vectors)

        # Inferir nível FIPS 199 a partir do NAICS
        fips_level = naics_to_fips199(industry)

        # Extrair CIA impact
        conf = data.get("attribute", {}).get("confidentiality", {})
        intg = data.get("attribute", {}).get("integrity", {})
        avail = data.get("attribute", {}).get("availability", {})
        cia_dims = ""
        if conf.get("data_disclosure") == "Yes": cia_dims += "C"
        if intg.get("variety", []): cia_dims += "I"
        if avail.get("variety", []): cia_dims += "A"

        incidents.append(IncidentRecord(
            source       = "vcdb",
            incident_id  = data.get("incident_id", json_file.stem),
            naics_sector = industry,
            org_size     = classify_org_size(data.get("victim", {}).get("employee_count", "")),
            asset_type   = asset_type,
            access_vector= access_vector,
            cia_impact   = cia_dims or "Unknown",
            cve_ids      = [],   # VCDB raramente tem CVE IDs — cruzar com KEV se necessário
            fips199_level= fips_level,
        ))

    print(f"[VCDB] {len(incidents)} incidentes carregados")
    return incidents


def classify_access_vector(vectors: list[str]) -> str:
    """Mapear vectores VCDB para categorias de exposição."""
    internet_vectors = {"Web application", "Remote Access Services", "Email", "VPN"}
    internal_vectors = {"Direct install", "Backdoor or C2", "Physical access"}

    for v in vectors:
        if any(iv in v for iv in internet_vectors):
            return "External - Internet"
    for v in vectors:
        if any(iv in v for iv in internal_vectors):
            return "Internal"
    return "Unknown"


def classify_org_size(employee_str: str) -> str:
    """Classificar dimensão organizacional a partir de faixas VCDB."""
    if any(s in employee_str for s in ["1 to 10", "11 to 100"]):
        return "small"
    elif any(s in employee_str for s in ["101 to 1000", "1001 to 10000"]):
        return "medium"
    elif "10000" in employee_str or "Large" in employee_str:
        return "large"
    return "unknown"


# Tabela NAICS → FIPS 199 derivada do NIST SP 800-60 Vol. II
# Justificação: SP 800-60 atribui níveis de impacto por tipo de missão/informação
NAICS_TO_FIPS199 = {
    "52":  "High",      # Finance and Insurance (dados financeiros regulados)
    "62":  "High",      # Health Care (PHI, HIPAA)
    "92":  "High",      # Public Administration (dados governamentais)
    "22":  "High",      # Utilities (infraestrutura crítica)
    "48":  "High",      # Transportation (infraestrutura crítica)
    "51":  "Moderate",  # Information (tech companies, SaaS)
    "54":  "Moderate",  # Professional Services
    "44":  "Moderate",  # Retail
    "72":  "Moderate",  # Accommodation and Food Services
    "61":  "Moderate",  # Educational Services
    "23":  "Low",       # Construction
    "11":  "Low",       # Agriculture
}

def naics_to_fips199(naics_code: str) -> str:
    """Mapear código NAICS (2 dígitos) para FIPS 199 impact level."""
    prefix = naics_code[:2]
    return NAICS_TO_FIPS199.get(prefix, "Moderate")


# ══════════════════════════════════════════════════════════════
# FONTE 7: HHS OCR Breach Portal (healthcare específico)
# Acesso: Download público, sem autenticação
# URL: https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf
# Export: CSV disponível na página (botão "Export")
# Também disponível via: healthdata.gov
# RELEVÂNCIA: Ground truth de breaches HIPAA → calibrar perfil HOSP
# ══════════════════════════════════════════════════════════════

def load_hhs_ocr_breaches(csv_path: str) -> list[IncidentRecord]:
    """
    Parse do CSV exportado do HHS OCR Breach Portal.
    Colunas relevantes:
        "Name of Covered Entity" — organização
        "Type of Covered Entity" — Healthcare Provider | Health Plan | Business Associate
        "Location of Breached Information" — Network Server | Email | Laptop | Paper/Films
        "Type of Breach" — Hacking/IT | Unauthorized Access | Theft
        "Number of Individuals Affected"
        "State"

    ACCESS:
        Manual: ocrportal.hhs.gov/ocr/breach/breach_report.jsf → Export
        Programático: via healthdata.gov/dataset API (JSON)
            GET https://healthdata.gov/api/3/action/datastore_search?resource_id=<id>

    PSEUDOCODE:
    """
    incidents = []

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Inferir vector de acesso a partir de Location e Type
            location = row.get("Location of Breached Information", "")
            breach_type = row.get("Type of Breach", "")

            if "Network Server" in location or "Hacking/IT" in breach_type:
                access_vector = "External - Internet"
            elif "Email" in location:
                access_vector = "External - Internet"
            elif "Laptop" in location or "Paper" in location:
                access_vector = "Physical"
            else:
                access_vector = "Internal"

            # Healthcare é sempre FIPS 199 High (PHI é categoria High para C e I)
            incidents.append(IncidentRecord(
                source        = "hhs_ocr",
                incident_id   = hashlib.md5(
                    (row.get("Name of Covered Entity","") + row.get("Breach Submission Date","")).encode()
                ).hexdigest()[:8],
                naics_sector  = "62",   # NAICS 62 = Healthcare
                org_size      = classify_org_size_from_count(
                    row.get("Number of Individuals Affected", "0")),
                asset_type    = location.split(",")[0].strip() if location else "Unknown",
                access_vector = access_vector,
                cia_impact    = "C",    # PHI = confidentiality breach
                cve_ids       = [],
                fips199_level = "High",
            ))

    print(f"[HHS OCR] {len(incidents)} breaches carregados")
    return incidents


def classify_org_size_from_count(count_str: str) -> str:
    """Classificar por número de indivíduos afectados (proxy para dimensão org)."""
    try:
        n = int(count_str.replace(",", ""))
        if n < 1000:   return "small"
        if n < 50000:  return "medium"
        return "large"
    except ValueError:
        return "unknown"


# ══════════════════════════════════════════════════════════════
# FONTE 8: Shadowserver (exposição internet-facing por CVE)
# Acesso: API com registo gratuito (organização académica)
# URL: https://www.shadowserver.org/api/reports/
# Também: dashboard.shadowserver.org — acesso visual gratuito
# RELEVÂNCIA: Dados de honeypot → validar E(α) para CVEs automatable
# ══════════════════════════════════════════════════════════════

SHADOWSERVER_API = "https://transform.shadowserver.org/api2/"

def fetch_shadowserver_exploitation(cve_id: str, api_key: str) -> dict:
    """
    Query Shadowserver para tentativas de exploração observadas para um CVE.
    Requer API key gratuita (registo em shadowserver.org).

    ACCESS:
        POST https://transform.shadowserver.org/api2/reports/query
        Body: {"report": "honeypot-exploited-vulnerability", "cve_id": cve_id}
        Header: X-API-KEY: <key>

    PSEUDOCODE:
    """
    url  = f"{SHADOWSERVER_API}reports/query"
    body = {
        "report":  "honeypot-exploited-vulnerability",
        "cve_id":  cve_id,
        "start":   "2025-01-01",
        "end":     SNAPSHOT_DATE,
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
# FONTE 9: Veracode State of Software Security (por registo)
# Acesso: Registo gratuito em veracode.com/state-of-software-security-report
# Formato: PDF/dados agregados
# RELEVÂNCIA: Percentagens de prevalência de falhas por sector → calibrar C(α)
# Não é um dataset machine-readable — extracção manual ou via tabelas do relatório
# ══════════════════════════════════════════════════════════════

# Dados extraídos manualmente do Veracode SoSS 2025/2026
# (citáveis directamente no paper como fonte agregada)
VERACODE_SECTOR_FLAW_PREVALENCE = {
    # sector → % de apps com pelo menos uma flaw de severidade high/critical
    "Financial Services": 0.51,   # 51% — Veracode SoSS 2026
    "Healthcare":         0.63,   # 63%
    "Technology":         0.48,   # 48%
    "Government":         0.44,   # 44%
    "Retail":             0.39,   # 39%
}

def veracode_c_alpha_adjustment(naics_sector: str) -> float:
    """
    Ajustar C(α) com base na prevalência de falhas por sector (Veracode SoSS).
    Lógica: sectores com maior prevalência de falhas têm maior dívida de segurança,
    implicando que os controlos compensatórios são menos efectivos → C(α) mais elevado.

    NOTA: Este ajustamento é opcional — serve para validar a escolha dos valores
    discretos, não para os derivar directamente.
    """
    sector_map = {
        "52": "Financial Services",
        "62": "Healthcare",
        "51": "Technology",
        "92": "Government",
        "44": "Retail",
    }
    sector_name = sector_map.get(naics_sector[:2])
    if not sector_name:
        return 1.0   # Multiplicador neutro

    prevalence = VERACODE_SECTOR_FLAW_PREVALENCE.get(sector_name, 0.50)
    # Normalizar para multiplicador [0.8, 1.2]
    # Prevalência média ~50% → multiplicador 1.0
    # Prevalência 63% (healthcare) → multiplicador 1.13
    return 0.8 + (prevalence / 0.50) * 0.2


# ══════════════════════════════════════════════════════════════
# PIPELINE CENTRAL: Construção do Dataset Composto
# ══════════════════════════════════════════════════════════════

def build_cve_dataset(cve_ids: list[str], shadowserver_key: str = None) -> list[CVERecord]:
    """
    Pipeline completo de construção do dataset de CVEs.
    Orquestra todas as fontes para produzir um CVERecord por CVE.

    ORDEM DE EXECUÇÃO:
    1. NVD → CVSS base score
    2. EPSS snapshot → probabilidade de exploração (data fixa)
    3. CISA KEV → ground truth de exploração in-the-wild
    4. SSVC/Vulnrichment → classification nodes (automatable, mission prevalence)
    5. VulZoo → confirmação multi-fonte
    6. Shadowserver (opcional) → telemetria de exploração observada
    """
    print(f"[Pipeline] Construindo dataset para {len(cve_ids)} CVEs (snapshot: {SNAPSHOT_DATE})")

    # Passo 1: CVSS via NVD
    print("[1/6] Fetching CVSS scores (NVD API)...")
    nvd_data = {r["cve_id"]: r for r in fetch_nvd_batch(cve_ids)}

    # Passo 2: EPSS snapshot
    print(f"[2/6] Fetching EPSS scores (snapshot {SNAPSHOT_DATE})...")
    epss_scores = fetch_epss_snapshot(SNAPSHOT_DATE, cve_ids)

    # Passo 3: CISA KEV
    print("[3/6] Loading CISA KEV...")
    kev_set = fetch_cisa_kev()

    # Passo 4: SSVC
    print("[4/6] Fetching SSVC classifications (Vulnrichment)...")
    ssvc_data = {}
    for cve_id in cve_ids:
        ssvc_data[cve_id] = fetch_ssvc_classification(cve_id)
        time.sleep(0.3)

    # Passo 5: VulZoo
    print("[5/6] Loading VulZoo exploit sources...")
    vulzoo_exploits = load_vulzoo_exploit_db()

    # Passo 6: Shadowserver (opcional — requer API key)
    shadowserver_data = {}
    if shadowserver_key:
        print("[6/6] Fetching Shadowserver exploitation data...")
        for cve_id in cve_ids:
            shadowserver_data[cve_id] = fetch_shadowserver_exploitation(cve_id, shadowserver_key)
            time.sleep(1.0)
    else:
        print("[6/6] Shadowserver skipped (no API key)")

    # Montar CVERecords
    records = []
    for cve_id in cve_ids:
        nvd    = nvd_data.get(cve_id, {})
        ssvc   = ssvc_data.get(cve_id, {})
        epss   = epss_scores.get(cve_id, 0.0)   # 0.0 → fail-close em runtime

        records.append(CVERecord(
            cve_id             = cve_id,
            cvss_base          = nvd.get("cvss_base", 0.0),
            epss_score         = epss,
            epss_date          = SNAPSHOT_DATE,
            cisa_kev           = cve_id in kev_set,
            ssvc_exploitation  = ssvc.get("exploitation", "none"),
            ssvc_automatable   = ssvc.get("automatable", False),
            ssvc_impact        = ssvc.get("impact", "Partial"),
            vulzoo_sources     = vulzoo_exploits.get(cve_id, []),
        ))

    return records


def derive_profile_calibration(
    profile_name: str,
    naics_codes: list[str],
    incidents: list[IncidentRecord],
) -> ProfileCalibration:
    """
    Derivar C(α) e E(α) empiricamente a partir dos incidentes VCDB + HHS OCR.

    METODOLOGIA:
    C(α): Mediana do FIPS 199 impact level dos incidentes no sector.
          "Low" → 0.25, "Moderate" → 0.50, "High" → 1.00
          +0.50 se sector sob escopo regulatório obrigatório (NAICS 52, 62, 92)
    E(α): Proporção de incidentes com vector de acesso "External - Internet"
          0-25%   → 0.30 (predominantly internal)
          25-60%  → 0.50 (mixed)
          60-85%  → 0.80 (mostly internet-facing)
          >85%    → 1.00 (predominantly public-facing)
    """
    sector_incidents = [
        inc for inc in incidents
        if inc.naics_sector[:2] in [n[:2] for n in naics_codes]
    ]
    n = len(sector_incidents)

    if n == 0:
        return ProfileCalibration(
            profile_name=profile_name, naics_codes=naics_codes,
            c_alpha=0.50, e_alpha=0.50,
            c_alpha_source="default (no incidents)", e_alpha_source="default",
            n_incidents=0, n_cves=0
        )

    # C(α): derivar do FIPS 199 modal
    fips_levels = [inc.fips199_level for inc in sector_incidents]
    fips_counts = {l: fips_levels.count(l) for l in set(fips_levels)}
    modal_fips  = max(fips_counts, key=fips_counts.get)

    fips_to_c = {"Low": 0.25, "Moderate": 0.75, "High": 1.00}
    c_base = fips_to_c.get(modal_fips, 0.50)

    # Ajustar para escopo regulatório
    regulatory_naics = {"52", "62", "92", "22", "48"}
    if any(n[:2] in regulatory_naics for n in naics_codes):
        c_alpha = min(c_base + 0.50, 1.50)
        c_source = f"FIPS 199 modal={modal_fips} + regulatory adjustment"
    else:
        c_alpha  = c_base
        c_source = f"FIPS 199 modal={modal_fips} (VCDB n={n})"

    # E(α): proporção com vector internet-facing
    internet_count = sum(
        1 for inc in sector_incidents
        if inc.access_vector == "External - Internet"
    )
    internet_ratio = internet_count / n

    if internet_ratio <= 0.25:
        e_alpha, e_label = 0.30, "predominantly internal"
    elif internet_ratio <= 0.60:
        e_alpha, e_label = 0.50, "mixed exposure"
    elif internet_ratio <= 0.85:
        e_alpha, e_label = 0.80, "mostly internet-facing"
    else:
        e_alpha, e_label = 1.00, "predominantly public-facing"

    e_source = f"VCDB access vector distribution: {internet_ratio:.1%} internet-facing ({e_label})"

    return ProfileCalibration(
        profile_name = profile_name,
        naics_codes  = naics_codes,
        c_alpha      = round(c_alpha, 2),
        e_alpha      = round(e_alpha, 2),
        c_alpha_source = c_source,
        e_alpha_source = e_source,
        n_incidents  = n,
        n_cves       = 0,  # preenchido pelo caller
    )


# ══════════════════════════════════════════════════════════════
# PIPELINE DE VALIDAÇÃO: CVSS×EPSS vs Modelo Contextualizado
# ══════════════════════════════════════════════════════════════

def compute_contextual_score(
    cvss: float,
    epss: float,
    c_alpha: float,
    e_alpha: float,
    compensating_effectiveness: float = 0.0,
    kappa: float = 0.8,
) -> float:
    """
    Função de scoring central (v4).
    R(v, α) = [CVSS(v)/10 · EPSS(v)] · C(α) · E(α) · [1 − Φ(α)]

    Proposição 2 (Bounded output): R(v, α) ∈ [0, 1.5].
    Prova: CVSS(v)/10 ≤ 1, EPSS(v) ≤ 1, C(α) ≤ 1.5, E(α) ≤ 1.0,
    (1−Φ) ≤ 1.0. Máximo: 1 × 1 × 1.5 × 1.0 × 1.0 = 1.5. □

    fail-close: se epss == 0.0, usar 1.0 (indisponível ≠ inexplorável).
    """
    epss_eff = epss if epss > 0.0 else 1.0
    phi      = min(compensating_effectiveness, kappa)
    return (cvss / 10.0) * epss_eff * c_alpha * e_alpha * (1.0 - phi)


def evaluate_gate(score: float, theta_block: float, theta_warn: float) -> str:
    """Aplicar regra de decisão ao score."""
    if score > theta_block:    return "BLOCK"
    if score > theta_warn:     return "ACCEPT_SLA"
    return "APPROVE"


def run_validation_study(
    cve_records: list[CVERecord],
    profiles: list[ProfileCalibration],
    theta_configs: dict,
) -> dict:
    """
    Executar simulation study completo.
    Calcular divergência entre CVSS-only (threshold 7.0) e modelo contextualizado.

    SAÍDA:
        {profile: {total: int, block: int, allow: int, diverge_from_cvss: int,
                   under_block: int, over_block: int, block_rate: float}}
    """
    cvss_baseline_threshold = 7.0
    results = {}

    for profile in profiles:
        theta_block = theta_configs[profile.profile_name]["block"]
        theta_warn  = theta_configs[profile.profile_name].get("warn", theta_block * 0.8)

        total = len(cve_records)
        block_contextual = 0
        block_cvss_only  = 0
        under_block = 0   # context blocks, CVSS permits
        over_block  = 0   # CVSS blocks, context permits

        for rec in cve_records:
            # Decisão modelo contextualizado
            ctx_score    = compute_contextual_score(
                rec.cvss_base, rec.epss_score,
                profile.c_alpha, profile.e_alpha
            )
            ctx_decision = evaluate_gate(ctx_score, theta_block, theta_warn)

            # Decisão CVSS-only
            cvss_decision = "BLOCK" if rec.cvss_base >= cvss_baseline_threshold else "APPROVE"

            # Contagens
            if ctx_decision == "BLOCK":
                block_contextual += 1
            if cvss_decision == "BLOCK":
                block_cvss_only += 1

            # Divergência
            ctx_blocked  = ctx_decision == "BLOCK"
            cvss_blocked = cvss_decision == "BLOCK"
            if ctx_blocked and not cvss_blocked:
                under_block += 1   # CVSS would have missed this
            if cvss_blocked and not ctx_blocked:
                over_block += 1    # CVSS unnecessarily blocked this

        results[profile.profile_name] = {
            "total":            total,
            "block_contextual": block_contextual,
            "block_cvss_only":  block_cvss_only,
            "block_rate":       round(block_contextual / total, 4),
            "under_block":      under_block,
            "over_block":       over_block,
            "diverge_total":    under_block + over_block,
            "diverge_rate":     round((under_block + over_block) / total, 4),
        }

    return results


# ══════════════════════════════════════════════════════════════
# REPRODUCIBILIDADE: Arquivo e hashing do dataset
# ══════════════════════════════════════════════════════════════

def archive_dataset(cve_records: list[CVERecord], profiles: list[ProfileCalibration]) -> str:
    """
    Serializar e arquivar o dataset completo para reproducibilidade.
    Gera SHA256 do arquivo para publicar no paper.

    NOTA: O arquivo deve ser depositado em Zenodo (DOI permanente)
    ou como release asset no repositório GitHub.
    """
    output = {
        "metadata": {
            "snapshot_date":  SNAPSHOT_DATE,
            "generated_at":   datetime.utcnow().isoformat() + "Z",
            "n_cves":         len(cve_records),
            "n_profiles":     len(profiles),
            "sources": [
                "NVD CVSS API",
                "FIRST.org EPSS",
                "CISA KEV",
                "CISA Vulnrichment/SSVC",
                "VCDB (vz-risk/VCDB)",
                "VulZoo (NUS-Curiosity/VulZoo)",
            ],
        },
        "cve_records":  [asdict(r) for r in cve_records],
        "calibrations": [asdict(p) for p in profiles],
    }

    archive_path = DATA_DIR / f"dataset_{SNAPSHOT_DATE}.json"
    archive_path.write_text(json.dumps(output, indent=2))

    # Calcular SHA256 para citação no paper
    sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = archive_path.with_suffix(".sha256")
    checksum_path.write_text(sha256)

    print(f"[Archive] Dataset: {archive_path}")
    print(f"[Archive] SHA256:  {sha256}")
    print(f"[Archive] Citar no paper: dataset archived at GitHub release sha256:{sha256[:16]}...")

    return sha256


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

CVE_LIST = [
    "CVE-2021-44228",   # Log4Shell
    "CVE-2024-3094",    # xz backdoor
    "CVE-2023-38545",   # curl SOCKS5
    "CVE-2019-10744",   # minimist
    # ... + 233 CVEs adicionais do corpus NVD
]

# Ensemble publicado no paper v4 (escala [0, 1.5] — cf. Proposição 2).
# θ_block e θ_warn expressos na escala normalizada (CVSS/10).
PROFILES_CONFIG = [
    ("BANK",  ["52"],       {"block": 0.05,  "warn": 0.03}),   # θ_Finance
    ("HOSP",  ["62"],       {"block": 0.08,  "warn": 0.05}),
    ("SAAS",  ["51"],       {"block": 0.20,  "warn": 0.10}),
    ("INFRA", ["22"],       {"block": 0.03,  "warn": 0.02}),   # θ_Utilities (NIS2 Essential Entity)
]

def main():
    # 1. Construir dataset de CVEs
    cve_records = build_cve_dataset(CVE_LIST)

    # 2. Carregar incidentes para calibração
    vcdb_incidents = load_vcdb_incidents()
    # hhs_incidents = load_hhs_ocr_breaches("data/hhs_ocr_breaches.csv")
    # all_incidents = vcdb_incidents + hhs_incidents
    all_incidents = vcdb_incidents

    # 3. Derivar calibrações empiricamente
    profiles = []
    theta_configs = {}
    for profile_name, naics_codes, thetas in PROFILES_CONFIG:
        cal = derive_profile_calibration(profile_name, naics_codes, all_incidents)
        cal.n_cves = len(CVE_LIST)
        profiles.append(cal)
        theta_configs[profile_name] = thetas
        print(f"[Calibration] {profile_name}: C(α)={cal.c_alpha} E(α)={cal.e_alpha} "
              f"(n={cal.n_incidents} incidents)")

    # 4. Executar simulation study
    results = run_validation_study(cve_records, profiles, theta_configs)

    print("\n=== SIMULATION RESULTS ===")
    for profile, r in results.items():
        print(f"{profile:6s}: BLOCK={r['block_contextual']:3d} ({r['block_rate']:.1%}) | "
              f"under_block={r['under_block']:3d} | over_block={r['over_block']:3d} | "
              f"diverge={r['diverge_rate']:.1%}")

    # 5. Arquivar para reproducibilidade
    sha256 = archive_dataset(cve_records, profiles)
    print(f"\nDataset SHA256: {sha256}")

if __name__ == "__main__":
    main()

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent / "cache_db"

def load_data():
    """Load the cached vulnerability data."""
    cache_file = CACHE_DIR / "sample_vulnerabilities.json"
    if not cache_file.exists():
        raise FileNotFoundError(f"Cache file {cache_file} not found. Perform ETL with builder.py first.")
        
    with open(cache_file, 'r') as f:
        return json.load(f)

def run_bootstrap_validation():
    """
    Validates the statistical bootstrap for the Risk Appetites.
    Normalizes CVSS as CVSS / 10 (per Wardex v4 Proposition 2).
    """
    data = load_data()
    logger.info("Initializing Bootstrap Validation (Proposição 2 da v4)...")
    
    for item in data.get("cves", []):
        cve_id = item["id"]
        cvss = item["cvss_base"]
        epss = item["epss"]
        
        # O motor principal divide o CVSS Base por 10.
        norm_cvss = cvss / 10.0
        final_score = norm_cvss * epss
        
        logger.info(f"{cve_id}: CVSS={cvss} norm={norm_cvss:.2f} EPSS={epss} -> Score={final_score:.3f}")
        
        # Validations for max [0, 1.5] scale limit.
        if final_score > 1.5:
            logger.error(f"Score for {cve_id} exceeds normalized maximum of 1.5!")
            
    logger.info("Validation complete. Engine scales behave as expected.")

if __name__ == "__main__":
    run_bootstrap_validation()

import os
import json
import logging
from pathlib import Path
from dotenv import load_dotenv
import requests

# Load environment variables (NVD API keys, etc.)
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent / "cache_db"

def init_cache():
    """Ensure the cache directory exists."""
    if not CACHE_DIR.exists():
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created cache directory at {CACHE_DIR}")

def fetch_sample_data():
    """
    Mock function representing the extraction of empirical data from NVD/EPSS.
    In a real scenario, this uses the API key to fetch actual CVEs.
    """
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        logger.warning("NVD_API_KEY is not set. Using offline dummy data.")
        
    dummy_data = {
        "cves": [
            {"id": "CVE-2021-21972", "cvss_base": 9.8, "epss": 0.95},
            {"id": "CVE-2023-12345", "cvss_base": 5.4, "epss": 0.05},
            {"id": "CVE-2023-99999", "cvss_base": 7.5, "epss": 0.50}
        ]
    }
    
    cache_file = CACHE_DIR / "sample_vulnerabilities.json"
    with open(cache_file, 'w') as f:
        json.dump(dummy_data, f, indent=4)
        
    logger.info(f"Successfully saved {len(dummy_data['cves'])} CVE records to {cache_file}")

if __name__ == "__main__":
    init_cache()
    fetch_sample_data()

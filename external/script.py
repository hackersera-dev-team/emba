import os
import re
import sys
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
    USE_TQDM = True
except ImportError:
    USE_TQDM = False

# === Config ===
ROOT_DIR = os.path.expanduser("~/tools/emba/external/nvd-json-data-feeds")
OUT_FILE = "./component_list/nvd_product_list.txt"  # Format: product | vendor
LOG_FILE = "./component_list/nvd_product_extract.log"
MAX_WORKERS = 10

# CPE regex: extract vendor and product from CPE 2.3 URI
CPE_REGEX = re.compile(r'"criteria"\s*:\s*"cpe:2\.3:[aho]:([^:"]+):([^:"]+)', re.IGNORECASE)

# === Setup Logging ===
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

def extract_products_from_file(filepath):
    result = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                for match in CPE_REGEX.finditer(line):
                    vendor, product = match.groups()
                    result.add((product.lower(), vendor.lower()))  # Normalize casing
    except Exception as e:
        logger.warning(f"[!] Error reading {filepath}: {e}")
    return result

def main():
    logger.info("[+] Scanning for JSON files...")
    json_files = list(Path(ROOT_DIR).rglob("*.json"))
    logger.info(f"[+] Found {len(json_files)} files. Starting extraction with {MAX_WORKERS} threads...")

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    all_entries = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(extract_products_from_file, path): path for path in json_files}
        iterator = tqdm(as_completed(futures), total=len(futures), desc="Extracting") if USE_TQDM else as_completed(futures)

        for future in iterator:
            all_entries.update(future.result())

    sorted_entries = sorted(all_entries)

    with open(OUT_FILE, 'w') as f:
        for product, vendor in sorted_entries:
            f.write(f"{product} | {vendor}\n")

    logger.info(f"[+] Done. Extracted {len(sorted_entries)} unique product|vendor entries.")
    logger.info(f"[+] Output saved to {OUT_FILE}")
    logger.info(f"[+] Log saved to {LOG_FILE}")

if __name__ == "__main__":
    main()

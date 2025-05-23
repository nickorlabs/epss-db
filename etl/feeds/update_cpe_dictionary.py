import os
import requests
import zipfile
import io
import logging

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
CPE_FEED_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
OUTPUT_XML = os.path.join(RAW_DATA_DIR, "cpe_dictionary.xml")
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "cpe_dictionary.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

import xml.etree.ElementTree as ET
import json

def fetch_cpe_dictionary():
    logging.info(f"Downloading CPE dictionary from {CPE_FEED_URL}")
    resp = requests.get(CPE_FEED_URL, stream=True, timeout=120)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        for name in z.namelist():
            if name.endswith(".xml"):
                logging.info(f"Extracting {name} from ZIP")
                with z.open(name) as f_in, open(OUTPUT_XML, "wb") as f_out:
                    f_out.write(f_in.read())
                logging.info(f"Saved CPE dictionary XML to {OUTPUT_XML}")
                break
        else:
            raise RuntimeError("No XML file found in CPE dictionary ZIP archive.")

    # Parse XML and convert to JSON
    logging.info("Parsing XML and converting to JSON...")
    tree = ET.parse(OUTPUT_XML)
    root = tree.getroot()
    cpes = []
    ns = {'cpe-dict': 'http://cpe.mitre.org/dictionary/2.0'}
    for cpe_item in root.findall('.//cpe-dict:cpe-item', ns):
        name = cpe_item.get('name')
        title_elem = cpe_item.find('cpe-dict:title', ns)
        title = title_elem.text if title_elem is not None else None
        cpes.append({'name': name, 'title': title})
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(cpes, f)
    logging.info(f"Extracted and wrote {len(cpes)} CPE items to {OUTPUT_JSON}")
    return OUTPUT_JSON

if __name__ == "__main__":
    fetch_cpe_dictionary()

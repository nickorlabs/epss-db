import json
import os
import argparse
import requests
import time
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urljoin, urlparse
import logging

from etl.common.io import download_file, write_json
from etl.common.translation import LibreTranslateAPI
from etl.common.osv_normalizer import create_osv_record

# Configuration
SECTION = "dur"
BASE_URL = "https://www.cert.ssi.gouv.fr"
LIST_URL_TEMPLATE = BASE_URL + f"/{SECTION}/page/{{page}}/"
CACHE_DIR = f"/etl-data/cache/certfr/{SECTION}"
RAW_DIR = f"/etl-data/raw/certfr/{SECTION}"
NORM_DIR = f"/etl-data/normalized/certfr/{SECTION}"
TRANSLATE_API_URL = os.getenv("TRANSLATE_API_URL", "http://libretranslate:5000")
TARGET_LANG_DEFAULT = os.getenv("TARGET_LANG", "en")
SOURCE_LANG_DEFAULT = "fr"

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(NORM_DIR, exist_ok=True)
logging.basicConfig(level=logging.INFO)

lt = LibreTranslateAPI(TRANSLATE_API_URL)

# Constants for translation verification
MIN_TRANSLATION_LENGTH_RATIO = 0.2
MAX_TRANSLATION_LENGTH_RATIO = 5.0
MIN_LENGTH_FOR_IDENTITY_CHECK = 10  # Min length of source text to consider for identity check
MIN_LENGTH_FOR_RATIO_CHECK = 20     # Min length of source text to consider for ratio check

def fetch_url(url, cache_path):
    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            return f.read()
    
    logging.debug(f"Fetching URL: {url}")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    text_content = ""
    # Prioritize decoding as UTF-8 from raw bytes, as CERT-FR seems to send UTF-8
    # bytes despite potentially incorrect 'ISO-8859-1' headers.
    try:
        text_content = resp.content.decode('utf-8')
        logging.debug(f"URL {url} - Successfully decoded content as UTF-8 from raw bytes.")
    except UnicodeDecodeError:
        logging.warning(f"URL {url} - Failed to decode as UTF-8 from raw bytes. Trying requests' detected encoding: {resp.encoding}")
        # Fallback to requests' detected encoding if UTF-8 fails
        try:
            text_content = resp.text # This will use resp.encoding or requests' default
            logging.debug(f"URL {url} - Used resp.text with encoding {resp.encoding or 'default by requests (likely ISO-8859-1)'}.")
        except Exception as e:
            logging.error(f"URL {url} - Could not decode content with UTF-8 nor with detected encoding. Error: {e}. Using replace for safety.")
            text_content = resp.content.decode('utf-8', errors='replace') # Last resort with replace

    with open(cache_path, "w", encoding="utf-8") as f:
        f.write(text_content)
    return text_content


def verify_translation(source_text, translated_text, source_lang, target_lang, field_name, advisory_slug):
    issues_found = False
    if not source_text: # If source is empty, translation is expected to be empty or None
        if translated_text:
            logging.warning(f"VERIFY_FAIL (SourceEmptyButTranslationNotEmpty): {advisory_slug} [{target_lang}] '{field_name}'. Source: '', Translation: '{translated_text[:50]}...'" )
            issues_found = True
        return not issues_found # Valid if source is empty and translation is also empty/None

    # Source text is not empty from here
    if not translated_text:
        logging.warning(f"VERIFY_FAIL (EmptyTranslation): {advisory_slug} [{target_lang}] '{field_name}'. Source: '{source_text[:50]}...'" )
        issues_found = True
        # Return immediately as other checks are not meaningful if translation is empty
        return False

    # Identity Check (only if source and target languages are different)
    if source_lang != target_lang and source_text == translated_text and len(source_text) >= MIN_LENGTH_FOR_IDENTITY_CHECK:
        logging.warning(f"VERIFY_FAIL (IdenticalTranslation): {advisory_slug} [{target_lang}] '{field_name}'. Text: '{source_text[:50]}...'" )
        issues_found = True

    # Length Ratio Check (only if source and target languages are different)
    if source_lang != target_lang and len(source_text) >= MIN_LENGTH_FOR_RATIO_CHECK:
        try:
            # Ensure translated_text is not empty to avoid ZeroDivisionError if it somehow passed the earlier check
            if not translated_text: # Should have been caught by 'EmptyTranslation' check
                return False 
            ratio = len(translated_text) / len(source_text)
            if not (MIN_TRANSLATION_LENGTH_RATIO <= ratio <= MAX_TRANSLATION_LENGTH_RATIO):
                logging.warning(f"VERIFY_FAIL (LengthRatio): {advisory_slug} [{target_lang}] '{field_name}'. Ratio: {ratio:.2f}. Source len: {len(source_text)}, Target len: {len(translated_text)}. Source: '{source_text[:50]}...', Target: '{translated_text[:50]}...'" )
                issues_found = True
        except ZeroDivisionError: # Should be caught by len(source_text) check, but as a safeguard
            logging.error(f"VERIFY_ERROR (ZeroDivisionError in LengthRatio): {advisory_slug} [{target_lang}] '{field_name}'. Source len: {len(source_text)}")
            issues_found = True # Consider this a verification failure
            
    return not issues_found


def parse_detail_page(html):
    # import logging # Removed redundant import
    soup = BeautifulSoup(html, "html.parser")
    # Title
    title_tag = soup.select_one('div.row.meta-title h1')
    title = title_tag.get_text(strip=True) if title_tag else ""
    logging.debug(f"Extracted title: {title}")
    # Date
    date = ""
    date_tag = soup.select_one('div.meta-droite > div')
    if date_tag:
        import re
        m = re.search(r'le (\d{2} \w+ \d{4})', date_tag.text)
        if m:
            date = m.group(1)
    if not date:
        date_cell = soup.find('td', string=lambda s: s and 'Date de la première version' in s)
        if date_cell and date_cell.find_next_sibling('td'):
            date = date_cell.find_next_sibling('td').get_text(strip=True)
    logging.debug(f"Extracted date: {date}")
    # Summary
    summary = ""
    content_section = soup.select_one('section.article-content')
    if content_section:
        first_p = content_section.find('p')
        summary = first_p.get_text(strip=True) if first_p else ""
        content_html = str(content_section)
    else:
        content_html = ""
    logging.debug(f"Extracted summary: {summary}")
    logging.debug(f"Extracted content_html length: {len(content_html)}")
    asset_links = []
    external_references_info = []
    image_assets_info = []
    if content_section:
        for a in content_section.find_all('a', href=True):
            href = a['href']
            is_pdf = href.lower().endswith('.pdf')
            is_upload_html = href.lower().startswith('/uploads/') and href.lower().endswith('.html')
            
            is_sensible_relative_link = href.startswith('/') and not href.startswith('//') and len(href) > 5

            logging.debug(f"Found link: '{href}', length: {len(href)}, is_pdf: {is_pdf}, is_upload_html: {is_upload_html}, is_sensible: {is_sensible_relative_link}")

            absolute_href = urljoin(BASE_URL, href)
            link_text = a.get_text(strip=True)

            if (is_pdf or is_upload_html) and is_sensible_relative_link:
                logging.debug(f"PASSED ASSET FILTER: Adding '{href}' to asset_links")
                asset_links.append(href) # Keep original href for assets
            else:
                logging.debug(f"SKIPPED ASSET FILTER: '{href}'. Adding to external_references_info as '{absolute_href}'")
                # Avoid adding empty or very short/schemeless relative links that aren't assets
                parsed_href = urlparse(absolute_href)
                if parsed_href.scheme and parsed_href.netloc and len(link_text) > 0:
                    external_references_info.append({"url": absolute_href, "text": link_text})
                else:
                    logging.debug(f"SKIPPED external_references_info addition for non-standard/empty link: '{absolute_href}' with text '{link_text}'")

        # Extract image assets
        for img in content_section.find_all('img', src=True):
            src = img['src']
            alt_text = img.get('alt', '')
            absolute_image_url = urljoin(BASE_URL, src)
            parsed_image_url = urlparse(absolute_image_url)
            image_filename = os.path.basename(parsed_image_url.path)
            image_cache_path = os.path.join(CACHE_DIR, image_filename)
            downloaded = False
            is_local_image = parsed_image_url.netloc == urlparse(BASE_URL).netloc or not parsed_image_url.scheme # Relative paths are local

            logging.debug(f"Found image: src='{src}', absolute='{absolute_image_url}', alt='{alt_text}', is_local_image: {is_local_image}")

            if is_local_image and image_filename: # Ensure there's a filename to save
                if download_file(absolute_image_url, image_cache_path):
                    logging.info(f"Successfully downloaded/cached image {absolute_image_url} to {image_cache_path}")
                    downloaded = True
                else:
                    logging.warning(f"Failed to download/cache image {absolute_image_url}")
            
            image_assets_info.append({
                "original_src": src,
                "absolute_url": absolute_image_url,
                "alt_text": alt_text,
                "cached_path": image_cache_path if downloaded else None,
                "downloaded": downloaded
            })
    logging.debug(f"Extracted asset_links: {asset_links}")
    tags = [] 
    return title, date, summary, content_html, tags, asset_links, external_references_info, image_assets_info


def parse_list_page(html):
    soup = BeautifulSoup(html, "html.parser")
    items = []
    for article in soup.select("article"):
        link = article.find("a", href=True)
        if link:
            items.append(urljoin(BASE_URL, link["href"]))
    return items


def main():
    parser = argparse.ArgumentParser(description="Fetch and translate CERT-FR /dur/ advisories.")
    parser.add_argument("--source-lang", type=str, default=SOURCE_LANG_DEFAULT,
                        help=f"Source language for translation (default: {SOURCE_LANG_DEFAULT})")
    parser.add_argument("--target-langs", type=lambda s: [item.strip() for item in s.split(',')], default=[TARGET_LANG_DEFAULT],
                        help=f"Comma-separated list of target languages for translation (default: {TARGET_LANG_DEFAULT})")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    BASE_URL = "https://www.cert.ssi.gouv.fr"
    SECTION = "dur"
    CACHE_DIR = f"/etl-data/cache/certfr/{SECTION}"
    RAW_DIR = f"/etl-data/raw/certfr/{SECTION}"
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(RAW_DIR, exist_ok=True)
    all_items = []
    osv_items = []
    seen_urls = set()
    page = 1
    while True:
        list_url = LIST_URL_TEMPLATE.format(page=page)
        logging.info(f"Fetching list page: {list_url}")
        list_cache = os.path.join(CACHE_DIR, f"list_page_{page}.html")
        try:
            html = fetch_url(list_url, list_cache)
        except requests.HTTPError as e:
            logging.info(f"No more pages or error: {e}")
            break
        soup = BeautifulSoup(html, "html.parser")
        articles = soup.select("article")
        for art in articles:
            # Extract detail URL
            a = art.select_one(".item-title a")
            if not a:
                continue
            detail_url = urljoin(BASE_URL, a.get("href"))
            slug = detail_url.rstrip("/").split("/")[-1]
            detail_cache = os.path.join(CACHE_DIR, f"{slug}.html")
            try:
                detail_html = fetch_url(detail_url, detail_cache)
            except Exception as e:
                logging.warning(f"Failed to fetch detail page {detail_url}: {e}")
                continue
            # Always parse the detail page for all fields
            title, date, summary, content_html, tags, asset_links, external_references_info, image_assets_info = parse_detail_page(detail_html)
            asset_local_paths = [] 
            for href in asset_links:
                asset_url = urljoin(BASE_URL, href) 
                asset_cache_path = os.path.join(CACHE_DIR, os.path.basename(urlparse(href).path))
                if download_file(asset_url, asset_cache_path):
                    asset_local_paths.append(asset_cache_path)
                    logging.info(f"Successfully ensured asset {asset_url} is at {asset_cache_path}")
                else:
                    logging.warning(f"Failed to download or verify asset {asset_url}")
            # Compose FR record with all fields
            rec_fr = {
                "title": title,
                "date": date,
                "summary": summary,
                "content_html": content_html,
                "asset_links": [urljoin(BASE_URL, href) for href in asset_links], 
                "tags": tags,
                "url": detail_url,
                "slug": slug,
                "asset_local_paths": asset_local_paths,
                "external_references_info": external_references_info,
                "image_assets_info": image_assets_info,
            }
            item_data = dict(rec_fr)  # Start with a copy of the French record
            item_data["translations"] = {}
            item_has_translation_issues = False

            for target_lang_code in args.target_langs:
                translated_fields = {}
                # This flag will track if any field *for this specific language* has issues.
                current_lang_has_issues = False 

                if args.source_lang == target_lang_code:
                    logging.info(f"Storing original {args.source_lang} text for {slug} under target_lang '{target_lang_code}' as source and target are same.")
                    temp_title = title
                    temp_summary = summary
                    temp_content_html = content_html
                    
                    # Verify original fields (e.g. to catch if source itself is empty)
                    if not verify_translation(title, temp_title, args.source_lang, target_lang_code, "title (original as translation)", slug):
                        current_lang_has_issues = True
                    if not verify_translation(summary, temp_summary, args.source_lang, target_lang_code, "summary (original as translation)", slug):
                        current_lang_has_issues = True
                    if not verify_translation(content_html, temp_content_html, args.source_lang, target_lang_code, "content_html (original as translation)", slug):
                        current_lang_has_issues = True
                    
                    translated_fields["title"] = temp_title
                    translated_fields["summary"] = temp_summary
                    translated_fields["content_html"] = temp_content_html
                else:
                    logging.debug(f"Translating {slug} to {target_lang_code} from {args.source_lang}")
                    
                    # Title translation and verification
                    translated_title = lt.translate(title, args.source_lang, target_lang_code) if title else ""
                    if not verify_translation(title, translated_title, args.source_lang, target_lang_code, "title", slug):
                        current_lang_has_issues = True
                    translated_fields["title"] = translated_title

                    # Summary translation and verification
                    translated_summary = lt.translate(summary, args.source_lang, target_lang_code) if summary else ""
                    if not verify_translation(summary, translated_summary, args.source_lang, target_lang_code, "summary", slug):
                        current_lang_has_issues = True
                    translated_fields["summary"] = translated_summary

                    # Content HTML translation and verification
                    translated_content_html = lt.translate(content_html, args.source_lang, target_lang_code) if content_html else ""
                    if not verify_translation(content_html, translated_content_html, args.source_lang, target_lang_code, "content_html", slug):
                        current_lang_has_issues = True
                    translated_fields["content_html"] = translated_content_html
                
                item_data["translations"][target_lang_code] = translated_fields
                if current_lang_has_issues:
                    item_has_translation_issues = True # If any lang has issues, mark the item
            
            item_data["translation_issues_detected"] = item_has_translation_issues
            all_items.append(item_data)

            # Normalize to OSV format
            feed_name = "certfr_dur"
            id_fields = ["slug"] # slug is unique like CERTFR-2024-AVI-0001
            field_map = {
                "modified": "date",
                "published": "date",
                "summary": "summary", # Original French summary
                "details": "content_html" # Original French content_html
            }
            # Fields to be included in OSV's database_specific section
            extra_osv_fields = [
                "title", # Original French title
                "tags", 
                "translations", 
                "translation_issues_detected", 
                "asset_links", 
                "asset_local_paths",
                "url", # Original advisory URL
                "external_references_info",
                "image_assets_info",
            ]

            # Prepare references for OSV format
            osv_references = []
            if item_data.get("url"):
                osv_references.append({"type": "ADVISORY", "url": item_data["url"]})
            for asset_url in item_data.get("asset_links", []):
                # Determine type based on extension, default to DOCUMENT
                reference_type = "DOCUMENT"
                if asset_url.lower().endswith('.pdf'):
                    reference_type = "REPORT" # Or ARTIFACT, depending on context
                elif asset_url.lower().endswith('.html'):
                    reference_type = "ARTICLE" # Or DOCUMENT
                osv_references.append({"type": reference_type, "url": asset_url})
            # Add external references from external_references_info
            for ext_ref in item_data.get("external_references_info", []):
                if ext_ref.get("url"):
                    ref_obj = {"type": "RELATED", "url": ext_ref["url"]}
                    # if ext_ref.get("text"): # Optionally add link text as name
                    #     ref_obj["name"] = ext_ref["text"]
                    osv_references.append(ref_obj)
            
            # Add image assets from image_assets_info
            for img_asset in item_data.get("image_assets_info", []):
                if img_asset.get("absolute_url"): # Only add if we have an absolute URL
                    ref_obj = {"type": "IMAGE", "url": img_asset["absolute_url"]}
                    # if img_asset.get("alt_text"): # Optionally add alt text as name
                    #     ref_obj["name"] = img_asset["alt_text"]
                    osv_references.append(ref_obj)

            # Create a temporary raw data copy for OSV that includes the pre-formatted references
            raw_for_osv = dict(item_data)
            raw_for_osv['references_osv_formatted'] = osv_references
            # Update field_map to point to this new field
            field_map_for_osv = dict(field_map)
            field_map_for_osv['references'] = 'references_osv_formatted'

            try:
                osv_record = create_osv_record(raw_for_osv, feed_name, field_map_for_osv, id_fields, extra_osv_fields)
                osv_items.append(osv_record)
            except Exception as e_osv:
                logging.error(f"Failed to create OSV record for {item_data.get('slug')}: {e_osv}")

        page += 1
        time.sleep(1)  # Be polite

    # Save combined raw JSON
    now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    output_path = os.path.join(RAW_DIR, f"dur_raw_multilang_{now}.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_items, f, ensure_ascii=False, indent=2)
    logging.info(f"Saved combined multi-language raw JSON: {output_path}")

    # Save OSV formatted JSON
    if osv_items:
        os.makedirs(NORM_DIR, exist_ok=True) # Ensure NORM_DIR exists
        osv_output_path = os.path.join(NORM_DIR, f"dur_osv_{now}.json")
        with open(osv_output_path, "w", encoding="utf-8") as f:
            json.dump(osv_items, f, ensure_ascii=False, indent=2)
        logging.info(f"Saved OSV formatted JSON: {osv_output_path}")
    else:
        logging.info("No OSV records were generated.")

if __name__ == "__main__":
    main()

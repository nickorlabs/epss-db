import os
import re
import json
import time
import logging
import argparse
import hashlib 
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from etl.common.io import fetch_url, download_file
from etl.common.translation import LibreTranslateAPI, verify_translation
from etl.common.osv_normalizer import create_osv_record

# --- SECTION SPECIFIC CONFIGURATION ---
SCRIPT_SECTION = "ioc"  # <<< CHANGE THIS FOR EACH NEW SCRIPT (alerte, cti, ioc, actualite)
# --- END SECTION SPECIFIC CONFIGURATION ---

BASE_URL = "https://www.cert.ssi.gouv.fr"
LIST_URL_TEMPLATE = f"{BASE_URL}/{SCRIPT_SECTION}/page/{{page}}/"

TRANSLATE_API_URL = os.environ.get("TRANSLATE_API_URL")
if not TRANSLATE_API_URL:
    logging.warning("TRANSLATE_API_URL environment variable not set. Translation will be skipped.")
    lt = None
else:
    lt = LibreTranslateAPI(TRANSLATE_API_URL)

SOURCE_LANG_DEFAULT = os.environ.get("SOURCE_LANG", "fr")
TARGET_LANG_DEFAULT = os.environ.get("TARGET_LANG", "en")

def parse_detail_page(html_content, current_section_for_logging_and_paths):
    """
    Parses the HTML content of a CERT-FR advisory detail page.
    TODO: CSS Selectors here are based on 'avis' structure and MUST be verified and adjusted for the '{current_section_for_logging_and_paths}' section.
    Check elements like title, date, summary, main content area, and how links/images are structured.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    
    # TODO: Verify selector for '{current_section_for_logging_and_paths}' section (e.g., 'div.row.meta-title h1')
    title_tag = soup.select_one('div.row.meta-title h1') 
    title = title_tag.get_text(strip=True) if title_tag else ""

    date_str = ""
    # TODO: Verify selector for '{current_section_for_logging_and_paths}' section (e.g., 'div.meta-droite > div')
    date_tag = soup.select_one('div.meta-droite > div') 
    if date_tag:
        date_text = date_tag.get_text(strip=True)
        # Attempt 1: DD/MM/YYYY format
        match_slash_date = re.search(r"Publié le (\d{{2}}/\d{{2}}/\d{{4}})", date_text) 
        if match_slash_date: 
            try:
                dt_object = datetime.strptime(match_slash_date.group(1), "%d/%m/%Y")
                date_str = dt_object.strftime("%Y-%m-%dT%H:%M:%SZ") 
            except ValueError:
                logging.warning(f"Date format DD/MM/YYYY found but failed to parse: {{match_slash_date.group(1)}} for section {{current_section_for_logging_and_paths}}")
                date_str = "" 
        else:
            # Attempt 2: DD month_name YYYY format (e.g., 1 janvier 2024)
            month_map = {
                "janvier": "01", "février": "02", "mars": "03", "avril": "04",
                "mai": "05", "juin": "06", "juillet": "07", "août": "08",
                "septembre": "09", "octobre": "10", "novembre": "11", "décembre": "12"
            }
            match_text_month = re.search(r"Publié le (\d{{1,2}})\s+([a-zA-Zûé]+)\s+(\d{{4}})", date_text, re.IGNORECASE)
            if match_text_month:
                day = match_text_month.group(1).zfill(2)
                month_name = match_text_month.group(2).lower()
                year = match_text_month.group(3)
                month = month_map.get(month_name)
                if month:
                    date_str = f"{{year}}-{{month}}-{{day}}T00:00:00Z" 
                else:
                    logging.warning(f"Date format DD month_name YYYY found, but month '{{month_name}}' not recognized for section {{current_section_for_logging_and_paths}}")
            else:
                 logging.warning(f"Could not parse date string: '{{date_text}}' using known patterns for section {{current_section_for_logging_and_paths}}.")

    summary = ""
    content_html_str = ""
    # TODO: Verify selector for '{current_section_for_logging_and_paths}' section (e.g., 'section.article-content')
    content_section = soup.select_one('section.article-content') 
    if content_section:
        first_p = content_section.find('p')
        summary = first_p.get_text(strip=True) if first_p else ""
        content_html_str = str(content_section) # Get the full HTML of the content section
    
    # TODO: Verify if tags exist and how to select them for '{current_section_for_logging_and_paths}' section. Placeholder: list of strings.
    tags = [] 

    asset_links = [] # URLs of downloadable assets (PDFs, zips, etc.)
    external_references_info = [] # List of dicts: {url, text, type} for other external links
    image_assets_info = [] # List of dicts for images: {original_src, absolute_url, local_path, alt_text}

    if content_section:
        # Extract links (assets and external references)
        for a_tag in content_section.find_all('a', href=True):
            href = a_tag['href']
            link_text = a_tag.get_text(strip=True)
            absolute_href = urljoin(BASE_URL, href) # Ensure URL is absolute
            parsed_href = urlparse(absolute_href)
            
            # Heuristic to identify asset links (e.g., PDFs, files in /uploads/)
            is_asset = parsed_href.path.lower().endswith(('.pdf', '.zip', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.html', '.htm')) or \
                       ("/uploads/" in parsed_href.path) or \
                       ("cert.ssi.gouv.fr/uploads/" in absolute_href) # More specific for CERT-FR uploads
            
            # Avoid mailto links and internal page anchors from being treated as assets/references
            if parsed_href.scheme in ['mailto'] or href.startswith("#"):
                continue

            if is_asset:
                # Check if it's an upload that might be an HTML page itself (often advisories link to HTML uploads)
                if href.lower().endswith(('.html', '.htm')) and "/uploads/" in href:
                    logging.debug(f"Treating HTML upload as asset: {{absolute_href}} for section {{current_section_for_logging_and_paths}}")
                asset_links.append(absolute_href) # Store absolute URL
            else:
                external_references_info.append({"url": absolute_href, "text": link_text, "type": "UNKNOWN"}) # Store absolute URL

        # Extract images and download them
        for img_tag in content_section.find_all('img', src=True):
            img_src = img_tag['src']
            alt_text = img_tag.get('alt', '')
            absolute_img_url = urljoin(BASE_URL, img_src) # Ensure URL is absolute
            
            img_cache_dir = f"/etl-data/cache/certfr/{{current_section_for_logging_and_paths}}/images" 
            os.makedirs(img_cache_dir, exist_ok=True)
            
            img_filename_base = os.path.basename(urlparse(absolute_img_url).path)
            img_filename_ext = os.path.splitext(img_filename_base)[1]
            if not img_filename_base or not img_filename_ext: # Handle cases like data URLs or URLs without clear extensions
                # Create a hash-based filename if original is problematic, try to keep extension if possible
                content_hash = hashlib.md5(absolute_img_url.encode()).hexdigest()
                img_filename = content_hash + (img_filename_ext if img_filename_ext else '.png') # Default to .png if no ext
            else:
                img_filename = img_filename_base

            img_local_path = os.path.join(img_cache_dir, img_filename)
            
            if download_file(absolute_img_url, img_local_path):
                logging.debug(f"Image successfully downloaded/verified: {{absolute_img_url}} -> {{img_local_path}} for section {{current_section_for_logging_and_paths}}")
                image_assets_info.append({
                    "original_src": img_src,
                    "absolute_url": absolute_img_url,
                    "local_path": img_local_path,
                    "alt_text": alt_text
                })
            else:
                logging.warning(f"Failed to download image: {{absolute_img_url}} for section {{current_section_for_logging_and_paths}}")

    return title, date_str, summary, content_html_str, tags, asset_links, external_references_info, image_assets_info

def main():
    # This variable is used for directory naming, logging, and potentially selectors
    # It's set from SCRIPT_SECTION at the top of the file for this specific script instance.
    current_script_section = SCRIPT_SECTION 

    parser = argparse.ArgumentParser(description=f"Fetch, parse, and translate CERT-FR /{current_script_section}/ advisories.")
    parser.add_argument("--source-lang", type=str, default=SOURCE_LANG_DEFAULT,
                        help=f"Source language for translation (default: {{SOURCE_LANG_DEFAULT}})")
    parser.add_argument("--target-langs", type=lambda s: [item.strip() for item in s.split(',')], default=[TARGET_LANG_DEFAULT],
                        help=f"Comma-separated list of target languages for translation (default: {{TARGET_LANG_DEFAULT}})")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger("requests").setLevel(logging.WARNING) # Silence noisy requests library
    logging.getLogger("urllib3").setLevel(logging.WARNING)   # Silence noisy urllib3 library
    logging.info(f"Starting CERT-FR ETL for section: {current_script_section}")
    
    CACHE_DIR = f"/etl-data/cache/certfr/{{current_script_section}}"
    RAW_DIR = f"/etl-data/raw/certfr/{{current_script_section}}"
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(os.path.join(CACHE_DIR, "images"), exist_ok=True) # Ensure images sub-cache dir exists

    all_processed_items = []
    osv_records = []
    page_number = 1
    max_pages_to_check = 200 # Safety break for while loop, adjust as needed
    consecutive_empty_pages = 0
    max_consecutive_empty_pages = 3 # Stop if 3 consecutive pages yield no new advisories
    
    # TODO: Verify the main listing page item selector for the '{current_script_section}' section.
    # Example for 'avis' was 'article.item.cert-avis'. For 'ioc' it might be 'article.item.cert-ioc', etc.
    # It's CRITICAL to get this right. Inspect the HTML of the listing pages for this section.
    listing_item_selector = f"article.item.cert-{{current_script_section}}" # Placeholder - VERIFY THIS!

    # TODO: Verify the selector for the link *within* each listing item for the '{current_script_section}' section.
    # Example for 'avis' was 'div.item-title a'.
    # It's CRITICAL to get this right. Inspect the HTML of the listing pages for this section.
    listing_item_link_selector = "div.item-title a" # Placeholder - VERIFY THIS!

    while page_number <= max_pages_to_check:
        list_url = LIST_URL_TEMPLATE.format(page=page_number)
        logging.info(f"Fetching list page: {{list_url}}")
        list_page_cache_path = os.path.join(CACHE_DIR, f"list_page_{{page_number}}.html")
        try:
            html_content = fetch_url(list_url, list_page_cache_path, is_listing_page=True)
            if not html_content: # fetch_url might return None if cache fails and network fails
                logging.error(f"Failed to fetch content for listing page {{list_url}}. Stopping.")
                break
        except requests.HTTPError as e:
            if e.response.status_code == 404: # Common for reaching end of pagination
                logging.info(f"Page {{page_number}} ({{list_url}}) not found (404), assuming end of advisories for section {{current_script_section}}.")
            else:
                logging.warning(f"HTTP error {{e.response.status_code}} fetching page {{page_number}} ({{list_url}}). Assuming end or issue.")
            break # Stop on 404 or other significant HTTP errors for listing pages
        except Exception as e:
            logging.error(f"An unexpected error occurred fetching listing page {{list_url}}: {{e}}. Stopping.")
            break

        soup = BeautifulSoup(html_content, "html.parser")
        articles_on_page = soup.select(listing_item_selector) 
        
        if not articles_on_page:
            logging.info(f"No articles found on page {{page_number}} using selector '{{listing_item_selector}}'.")
            consecutive_empty_pages += 1
            if page_number == 1: # If first page has no articles with this selector, it's a critical config error
                logging.critical(f"CRITICAL: No articles found on the FIRST page ({{list_url}}) for section '{{current_script_section}}' using selector '{{listing_item_selector}}'. The selector is likely incorrect. Please verify and update the script. Halting processing for this section.")
                break # Stop if the first page yields nothing, selector is bad
            if consecutive_empty_pages >= max_consecutive_empty_pages:
                logging.info(f"Reached {{max_consecutive_empty_pages}} consecutive empty pages. Assuming end of advisories for section {{current_script_section}}.")
                break
            page_number += 1
            time.sleep(1) # Brief pause before trying next page
            continue # Go to next page
        
        consecutive_empty_pages = 0 # Reset if we found articles
        found_new_advisory_on_this_page = False

        for article_tag in articles_on_page:
            link_tag = article_tag.select_one(listing_item_link_selector) 
            if not link_tag or not link_tag.get('href'):
                logging.warning(f"Could not find title link in article on {{list_url}} using selector '{{listing_item_link_selector}}'. Skipping article. Article HTML snippet: {{str(article_tag)[:500]}}...")
                continue
            
            detail_page_url = urljoin(BASE_URL, link_tag.get("href"))
            advisory_slug = detail_page_url.rstrip("/").split("/")[-1] # e.g., CERTFR-2023-AVI-0001
            detail_page_cache_path = os.path.join(CACHE_DIR, f"{{advisory_slug}}.html")
            
            try:
                detail_html_content = fetch_url(detail_page_url, detail_page_cache_path)
                if not detail_html_content:
                    logging.warning(f"Failed to fetch or load from cache detail page {{detail_page_url}}. Skipping advisory {{advisory_slug}}.")
                    continue
            except Exception as e:
                logging.warning(f"Failed to fetch detail page {{detail_page_url}} for advisory {{advisory_slug}}: {{e}}. Skipping.")
                continue
            
            found_new_advisory_on_this_page = True # If we process at least one, it's not an empty page of links
            title, date_str, summary, content_html, tags, asset_links, external_refs, image_assets = parse_detail_page(detail_html_content, current_script_section)
            
            # Download assets associated with the advisory
            downloaded_asset_local_paths = [] 
            for asset_url in asset_links: # asset_links should contain absolute URLs from parser
                asset_filename = os.path.basename(urlparse(asset_url).path)
                if not asset_filename: # Handle URLs that might not have a clear filename
                    asset_filename = hashlib.md5(asset_url.encode()).hexdigest() + ".download" # Fallback filename
                asset_cache_path = os.path.join(CACHE_DIR, asset_filename)
                if download_file(asset_url, asset_cache_path):
                    downloaded_asset_local_paths.append(asset_cache_path)
                    logging.info(f"Successfully ensured asset {{asset_url}} is at {{asset_cache_path}} for {{advisory_slug}}")
                else:
                    logging.warning(f"Failed to download or verify asset {{asset_url}} for {{advisory_slug}}")
            
            # --- Prepare base record (original language, typically French) ---
            base_record = {
                "id": advisory_slug, # Use slug as the primary ID for the record
                "title": title,
                "published_date": date_str, # Standardized ISO format date
                "summary": summary,
                "content_html": content_html,
                "source_url": detail_page_url,
                "tags": tags, # List of strings
                "assets_urls": asset_links, # List of original asset URLs (absolute)
                "assets_local_paths": downloaded_asset_local_paths, # List of local paths to downloaded assets
                "external_references": external_refs, # List of dicts {url, text, type}
                "image_assets": image_assets, # List of dicts {original_src, absolute_url, local_path, alt_text}
                "feed_section": current_script_section,
                "translations": {}
            }
            
            # --- Translation Handling ---
            item_has_translation_issues = False
            for target_lang_code in args.target_langs:
                translated_fields_for_lang = {}
                current_lang_has_translation_issue = False

                if args.source_lang == target_lang_code: # If source and target lang are same, use original
                    logging.debug(f"Storing original {{args.source_lang}} text for {{advisory_slug}} as 'translation' for target_lang '{{target_lang_code}}'.")
                    orig_title, orig_summary, orig_content = title, summary, content_html
                    if not verify_translation(title, orig_title, args.source_lang, target_lang_code, "title (original as translation)", advisory_slug): current_lang_has_translation_issue = True
                    if not verify_translation(summary, orig_summary, args.source_lang, target_lang_code, "summary (original as translation)", advisory_slug): current_lang_has_translation_issue = True
                    if not verify_translation(content_html, orig_content, args.source_lang, target_lang_code, "content_html (original as translation)", advisory_slug): current_lang_has_translation_issue = True
                    translated_fields_for_lang["title"] = orig_title
                    translated_fields_for_lang["summary"] = orig_summary
                    translated_fields_for_lang["content_html"] = orig_content
                elif lt: # If translator is available
                    logging.debug(f"Translating {{advisory_slug}} from {{args.source_lang}} to {{target_lang_code}}")
                    # Title
                    translated_title = lt.translate(title, args.source_lang, target_lang_code) if title else ""
                    if not verify_translation(title, translated_title, args.source_lang, target_lang_code, "title", advisory_slug): current_lang_has_translation_issue = True
                    translated_fields_for_lang["title"] = translated_title
                    # Summary
                    translated_summary = lt.translate(summary, args.source_lang, target_lang_code) if summary else ""
                    if not verify_translation(summary, translated_summary, args.source_lang, target_lang_code, "summary", advisory_slug): current_lang_has_translation_issue = True
                    translated_fields_for_lang["summary"] = translated_summary
                    # Content HTML
                    translated_content_html = lt.translate(content_html, args.source_lang, target_lang_code) if content_html else ""
                    if not verify_translation(content_html, translated_content_html, args.source_lang, target_lang_code, "content_html", advisory_slug): current_lang_has_translation_issue = True
                    translated_fields_for_lang["content_html"] = translated_content_html
                else: # Translator not available, mark as issue and provide empty fields
                    logging.warning(f"Translation skipped for {{advisory_slug}} to {{target_lang_code}} as translator (LibreTranslateAPI) is not available/configured.")
                    translated_fields_for_lang["title"], translated_fields_for_lang["summary"], translated_fields_for_lang["content_html"] = "", "", ""
                    current_lang_has_translation_issue = True # Mark as issue if translation was expected but not performed
                
                base_record["translations"][target_lang_code] = translated_fields_for_lang
                if current_lang_has_translation_issue:
                    item_has_translation_issues = True # If any language had an issue, mark the whole item
            
            base_record["translation_issues_detected"] = item_has_translation_issues
            all_processed_items.append(base_record)

            # --- Normalize to OSV format ---
            osv_feed_name = f"certfr_{{current_script_section}}" # e.g., certfr_ioc
            # Define how raw fields map to OSV standard fields
            osv_field_map = {
                "id": "id", # Uses the advisory_slug directly
                "modified": "published_date", # Assuming published is last modified for CERT-FR
                "published": "published_date",
                "summary": "summary", # This will be the original language summary
                "details": "content_html" # This will be the original language content_html
            }
            # Fields to be included in OSV's database_specific section
            # This includes original title, tags, and all translation-related data
            osv_extra_data_fields = [
                "title", # Original language title
                "tags", 
                "translations", 
                "translation_issues_detected", 
                "assets_urls", 
                "assets_local_paths",
                "source_url", 
                "external_references",
                "image_assets",
                "feed_section"
            ]

            # Prepare 'references' for OSV format from various link types
            osv_references_list = []
            if base_record.get("source_url"):
                osv_references_list.append({"type": "ADVISORY", "url": base_record["source_url"]})
            for asset_url in base_record.get("assets_urls", []):
                ref_type = "ARTIFACT" # Default for assets
                if asset_url.lower().endswith('.pdf'): ref_type = "REPORT"
                elif asset_url.lower().endswith(('.html', '.htm')): ref_type = "ARTICLE"
                osv_references_list.append({"type": ref_type, "url": asset_url})
            for ext_ref in base_record.get("external_references", []):
                osv_references_list.append({"type": ext_ref.get("type", "RELATED"), "url": ext_ref["url"]})
            for img_asset in base_record.get("image_assets", []):
                 if img_asset.get("absolute_url"):
                    osv_references_list.append({"type": "IMAGE", "url": img_asset["absolute_url"]})
            
            # Create a temporary dict for OSV normalization that includes the pre-formatted references
            raw_data_for_osv = dict(base_record)
            raw_data_for_osv['osv_formatted_references'] = osv_references_list
            osv_field_map_with_references = dict(osv_field_map)
            osv_field_map_with_references['references'] = 'osv_formatted_references' # Point to the new field

            try:
                osv_record = create_osv_record(raw_data_for_osv, osv_feed_name, osv_field_map_with_references, ["id"], osv_extra_data_fields)
                osv_records.append(osv_record)
            except Exception as e_osv:
                logging.error(f"Failed to create OSV record for {{advisory_slug}}: {{e_osv}}")

            time.sleep(0.5) # Small delay between processing individual advisories

        if not found_new_advisory_on_this_page and page_number > 1: # If page had items but all were already processed/skipped
            logging.info(f"No new advisories processed on page {{page_number}}. Considering this similar to an empty page for pagination logic.")
            consecutive_empty_pages +=1
            if consecutive_empty_pages >= max_consecutive_empty_pages:
                logging.info(f"Reached {{max_consecutive_empty_pages}} consecutive pages with no new advisories. Assuming end.")
                break

        page_number += 1
        time.sleep(1)  # Be polite to the server between fetching list pages

    # --- Save combined raw data (all processed items) ---
    timestamp_now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    raw_output_filename = f"{{current_script_section}}_raw_multilang_{{timestamp_now}}.json"
    raw_output_path = os.path.join(RAW_DIR, raw_output_filename)
    with open(raw_output_path, "w", encoding="utf-8") as f:
        json.dump(all_processed_items, f, ensure_ascii=False, indent=2)
    logging.info(f"Saved combined multi-language raw JSON for {{len(all_processed_items)}} items: {{raw_output_path}}")

    # --- Save combined OSV data ---
    if osv_records:
        osv_output_filename = f"{{current_script_section}}_osv_multilang_{{timestamp_now}}.json"
        osv_output_path = os.path.join(RAW_DIR, osv_output_filename) # Also save OSV in RAW_DIR for now
        with open(osv_output_path, "w", encoding="utf-8") as f:
            json.dump(osv_records, f, ensure_ascii=False, indent=2)
        logging.info(f"Saved combined OSV JSON for {{len(osv_records)}} items: {{osv_output_path}}")
    else:
        logging.info("No OSV records were generated.")

    logging.info(f"CERT-FR ETL for section: {current_script_section} finished.")

if __name__ == "__main__":
    main()

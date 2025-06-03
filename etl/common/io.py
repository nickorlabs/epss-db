import os
import json
from typing import Any
import requests
import logging

def write_json(data: Any, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def download_file(url: str, cache_path: str, timeout: int = 30) -> bool:
    """
    Downloads a file from a URL and saves it to a cache path.
    Returns True if successful or file already exists, False otherwise.
    """
    try:
        if os.path.exists(cache_path) and os.path.getsize(cache_path) > 0:
            logging.debug(f"File already exists in cache and is not empty: {cache_path}")
            return True
        
        logging.debug(f"Downloading {url} to {cache_path}")
        response = requests.get(url, timeout=timeout, stream=True)
        response.raise_for_status() # Check for HTTP errors

        # Ensure directory exists before writing
        file_dir = os.path.dirname(cache_path)
        if not os.path.exists(file_dir):
            os.makedirs(file_dir, exist_ok=True)
            
        with open(cache_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.debug(f"Successfully downloaded {url} to {cache_path}")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to download {url}: {e}")
        return False
    except IOError as e:
        logging.error(f"Failed to write file {cache_path}: {e}")
        # Attempt to remove partially written file if an IOError occurs
        if os.path.exists(cache_path):
            try:
                os.remove(cache_path)
                logging.debug(f"Removed partially written file: {cache_path}")
            except OSError as oe:
                logging.error(f"Error removing partially written file {cache_path}: {oe}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred downloading {url} to {cache_path}: {e}")
        if os.path.exists(cache_path):
            try:
                os.remove(cache_path)
            except OSError:
                pass # best effort
        return False

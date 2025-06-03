import logging
import re # For more advanced checks later, if needed

def verify_record_count(raw, normalized):
    """Check if raw and normalized lists have the same number of records."""
    result = len(raw) == len(normalized)
    logging.info(f"Raw record count: {len(raw)}, Normalized record count: {len(normalized)}. Match: {result}")
    return result

def _get_nested(d, key):
    """Helper to extract nested keys using dot notation."""
    keys = key.split('.')
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return None
    return d

def verify_ids(raw, normalized, raw_id_key='id', norm_id_key='id'):
    """Check if the set of IDs in raw and normalized data match. Supports nested keys with dot notation."""
    raw_ids = set(_get_nested(r, raw_id_key) for r in raw if _get_nested(r, raw_id_key) is not None)
    norm_ids = set(_get_nested(n, norm_id_key) for n in normalized if _get_nested(n, norm_id_key) is not None)
    result = raw_ids == norm_ids
    logging.info(f"Raw IDs count: {len(raw_ids)}, Normalized IDs count: {len(norm_ids)}. IDs match: {result}")
    if not result:
        missing_in_norm = raw_ids - norm_ids
        missing_in_raw = norm_ids - raw_ids
        if missing_in_norm:
            logging.warning(f"IDs present in raw but missing in normalized: {list(missing_in_norm)[:10]}")
        if missing_in_raw:
            logging.warning(f"IDs present in normalized but missing in raw: {list(missing_in_raw)[:10]}")
    return result


def verify_field_presence(records, required_fields):
    """Check that all records have the required fields."""
    missing = []
    for i, rec in enumerate(records):
        for field in required_fields:
            if field not in rec:
                missing.append((i, field))
    if missing:
        logging.warning(f"Missing fields in records: {missing[:10]}")
    return not missing

def check_translation(original_text, translated_text, source_lang, target_lang, context_id=None):
    """
    Verifies the basic quality of a translation.

    Args:
        original_text (str): The source text.
        translated_text (str): The translated text.
        source_lang (str): The source language code (e.g., 'fr').
        target_lang (str): The target language code (e.g., 'en').
        context_id (str, optional): An identifier for the item being translated (e.g., advisory ID) for logging.

    Returns:
        dict: A dictionary with 'status' ('OK', 'WARNING', 'ERROR') and 'message'.
    """
    log_prefix = f"[Translation Check][{context_id}]" if context_id else "[Translation Check]"

    if not isinstance(original_text, str):
        original_text = "" # Coerce to string if not already
    if not isinstance(translated_text, str):
        translated_text = "" # Coerce to string if not already

    # 1. Empty Translation Check
    if original_text and not translated_text:
        return {
            "status": "ERROR",
            "message": f"{log_prefix} Original text is not empty, but translation is empty. Source: '{original_text[:50]}...'"
        }

    # Handle cases where original text itself is empty
    if not original_text and not translated_text:
        return {"status": "OK", "message": f"{log_prefix} Both original and translated texts are empty."}
    if not original_text and translated_text:
         return {
            "status": "WARNING",
            "message": f"{log_prefix} Original text is empty, but translation is not: '{translated_text[:50]}...'"
        }


    # 2. Identical Translation Check (for different languages)
    # Heuristic: Ignore if original text is very short (e.g., <= 3 words or <= 20 chars) as it might be a proper noun, code, etc.
    # Also, ignore if source and target languages are the same.
    if source_lang != target_lang and original_text == translated_text:
        original_word_count = len(original_text.split())
        if original_word_count > 3 and len(original_text) > 20:
            return {
                "status": "WARNING",
                "message": (
                    f"{log_prefix} Translation is identical to original for {source_lang}->{target_lang}. "
                    f"Original: '{original_text[:50]}...'"
                )
            }

    # 3. Length Ratio Check
    # Heuristic: Ignore for very short original texts.
    # Ratios can be tuned.
    min_len_for_ratio_check = 20
    if len(original_text) > min_len_for_ratio_check:
        len_orig = len(original_text)
        len_trans = len(translated_text)
        lower_bound_ratio = 0.20 # Translated text is less than 20% of original length
        upper_bound_ratio = 3.0  # Translated text is more than 300% of original length

        if len_trans < len_orig * lower_bound_ratio:
            return {
                "status": "WARNING",
                "message": (
                    f"{log_prefix} Translated text length ({len_trans}) is significantly shorter "
                    f"than original ({len_orig}) for {source_lang}->{target_lang}. "
                    f"Original: '{original_text[:50]}...', Translated: '{translated_text[:50]}...'"
                )
            }
        if len_trans > len_orig * upper_bound_ratio:
            return {
                "status": "WARNING",
                "message": (
                    f"{log_prefix} Translated text length ({len_trans}) is significantly longer "
                    f"than original ({len_orig}) for {source_lang}->{target_lang}. "
                    f"Original: '{original_text[:50]}...', Translated: '{translated_text[:50]}...'"
                )
            }

    # 4. Repetitive Character Check (Simple)
    # Checks if more than 90% of the translated text (if > 10 chars) is the same character.
    # This is a very basic check for obvious API errors.
    if len(translated_text) > 10:
        for char_code in range(32, 127): # Printable ASCII
            char = chr(char_code)
            if translated_text.count(char) / len(translated_text) > 0.90:
                return {
                    "status": "WARNING",
                    "message": (
                        f"{log_prefix} Translated text appears to be highly repetitive with character '{char}' "
                        f"for {source_lang}->{target_lang}. Translated: '{translated_text[:50]}...'"
                    )
                }
    
    # If no issues found
    return {"status": "OK", "message": f"{log_prefix} Translation check passed for {source_lang}->{target_lang}."}

# etl/common/translation.py
from libretranslatepy import LibreTranslateAPI

# This makes LibreTranslateAPI available when `from etl.common.translation import LibreTranslateAPI` is used.
# No further code is needed here if we're just re-exporting.
# If there were custom wrappers or logic around LibreTranslateAPI, they would go here.

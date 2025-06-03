import os
import json

import datetime

def safe_write_json(filepath, data, **kwargs):
    """
    Safely write data as JSON to the given filepath.
    Ensures the output directory exists before writing.
    kwargs are passed to json.dump (e.g., indent=2)
    """
    def default(obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")
    kwargs.setdefault("default", default)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, **kwargs)

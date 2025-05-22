import logging
from typing import Callable, List, Any

def fetch_paginated(api_func: Callable, *args, limit: int = 100, **kwargs) -> List[Any]:
    """
    Pagination helper for APIs with cursor/offset.
    On first call, use start_cursor="true".
    On subsequent calls, use only cursor=... (not start_cursor).
    """
    all_results = []
    cursor = None
    first = True
    while True:
        call_kwargs = dict(kwargs)
        call_kwargs['limit'] = limit
        if first:
            call_kwargs['start_cursor'] = "true"
            first = False
        elif cursor:
            call_kwargs['cursor'] = cursor
        resp = api_func(*args, **call_kwargs)
        if hasattr(resp, 'data') and resp.data:
            all_results.extend(resp.data)
        else:
            break
        next_cursor = getattr(resp.meta, 'next_cursor', None)
        if not next_cursor:
            break
        cursor = next_cursor
    logging.info(f"Fetched {len(all_results)} records with pagination.")
    return all_results

import os

def load_api_key(secret_name: str, env_var: str) -> str:
    """
    Load an API key from Docker secrets or environment variable.
    """
    secret_path = f"/run/secrets/{secret_name}"
    try:
        with open(secret_path, 'r') as f:
            return f.read().strip()
    except Exception:
        return os.environ.get(env_var)

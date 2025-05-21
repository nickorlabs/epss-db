import os

def read_secret(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return os.environ.get(os.path.basename(path).upper())

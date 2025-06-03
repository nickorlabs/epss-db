import os
import subprocess
import logging

def ensure_git_repo_latest(repo_url, target_dir):
    """
    Clone the repo if target_dir does not exist, otherwise pull the latest changes.
    """
    if not os.path.exists(target_dir):
        logging.info(f"Cloning repo {repo_url} to {target_dir}")
        subprocess.run(["git", "clone", repo_url, target_dir], check=True)
    else:
        logging.info(f"Pulling latest changes in {target_dir}")
        subprocess.run(["git", "-C", target_dir, "pull"], check=True)

import subprocess
import sys

import os

scripts = [
    "/scripts/update_epss.py",
    "/scripts/update_kev.py",
    "/scripts/update_vulnrich.py",
    "/scripts/update_exploitdb.py",
    "/scripts/update_mitre.py",
    "/scripts/update_nvd.py"
]

log_dir = "/scripts/logs"
os.makedirs(log_dir, exist_ok=True)


import os

for script in scripts:
    log_path = os.path.join(log_dir, os.path.basename(script).replace('.py', '.log'))
    print(f"\n=== Running {script} === (logging to {log_path})")
    with open(log_path, "a") as logfile:
        logfile.write(f"\n=== Running {script} ===\n")
        logfile.write(f"[DEBUG] About to run: {[sys.executable, script]}\n")
        logfile.write(f"[DEBUG] Current working dir: {os.getcwd()}\n")
        if not os.path.exists(script):
            msg = f"[ERROR] Script not found: {script}\n"
            print(msg)
            logfile.write(msg)
            continue
        try:
            result = subprocess.run([sys.executable, "-u", script], stdout=logfile, stderr=logfile, text=True)
            logfile.write(f"\n=== Finished {script} with exit code {result.returncode} ===\n")
        except Exception as e:
            msg = f"[EXCEPTION] Failed to run {script}: {e}\n"
            print(msg)
            logfile.write(msg)
            continue
    if 'result' in locals() and result.returncode != 0:
        print(f"[ERROR] {script} failed. See log: {log_path}")
        with open(log_path) as logfile:
            print("Last 40 lines of log:")
            lines = logfile.readlines()
            print(''.join(lines[-40:]))
        sys.exit(result.returncode)
    elif 'result' in locals():
        print(f"[OK] {script} completed. See log: {log_path}")
    else:
        print(f"[SKIPPED] {script} did not run.")
print("\nAll ETL jobs completed.")

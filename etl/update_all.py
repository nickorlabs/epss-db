import subprocess
import sys

scripts = [
    "update_epss.py",
    "update_kev.py",
    "update_vulnrich.py",
    "update_exploitdb.py"
]

for script in scripts:
    print(f"\n=== Running {script} ===")
    result = subprocess.run([sys.executable, script], cwd=".", capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error running {script}:\n{result.stderr}")
        sys.exit(result.returncode)
print("\nAll ETL jobs completed.")

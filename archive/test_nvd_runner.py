import sys
import os
print("NVD TEST SCRIPT STARTED")
print(f"sys.executable: {sys.executable}")
print(f"os.getcwd(): {os.getcwd()}")
print(f"__file__: {__file__}")
print(f"ENV: {os.environ}")
sys.stderr.write("NVD TEST STDERR OUTPUT\n")

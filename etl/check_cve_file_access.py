import os

# Hardcoded test for CVE-2024-9492
cve_id = 'CVE-2024-9492'
year = '2024'
subdir = '9xxx'
filename = f'{cve_id}.json'
dirpath = '/scripts/mitre-cvelistV5/cves/2024/9xxx'
filepath = os.path.join(dirpath, filename)

print(f'Checking file: {filepath}')
print('os.path.exists:', os.path.exists(filepath))
try:
    with open(filepath, 'r', encoding='utf-8') as f:
        print('File opened successfully, first 100 chars:')
        print(f.read(100))
except Exception as e:
    print('Failed to open file:', e)

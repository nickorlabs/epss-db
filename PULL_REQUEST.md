# EPSS-DB Improvements

This pull request contains several improvements to make the EPSS data system more robust and portable:

## 1. Dynamic Path Detection

Added dynamic path detection to all scripts to eliminate hardcoded paths. This makes the system more portable and allows it to be installed in any directory without manual modifications.

Changes include:
- Scripts now determine their location using `$(cd "$(dirname "$0")" && pwd)`
- All references to absolute paths like `/opt/epss-db/` have been replaced with dynamic variables
- Cross-script references use the dynamic paths instead of absolute paths

## 2. URL Updates

Updated all EPSS data URLs from `epss.cyentia.com` to `epss.empiricalsecurity.com` to reflect the domain change. The old domain now redirects to the new one, but scripts were getting stuck on the redirection.

## 3. Added Test Suite

Created a comprehensive test suite in `/tests/test-scripts.sh` that verifies:
- Dynamic path detection in all scripts
- Configuration file access
- Correct URLs for all data sources (EPSS, KEV, Vulnrichment)
- Script cross-references
- URL accessibility

## How to Test

1. Clone this fork
2. Run the test suite: `./tests/test-scripts.sh`
3. All tests should pass, confirming the changes work correctly

These improvements make the system more reliable, easier to maintain, and more portable across different environments.

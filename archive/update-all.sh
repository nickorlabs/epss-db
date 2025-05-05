#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASEPATH="$SCRIPT_DIR"
echo "Using base path: $BASEPATH"

# Please uncomment it if necessary.
echo "Update EPSS data"
"$BASEPATH/update-epss.sh"
echo "Update KEV Catalog data"
"$BASEPATH/update-kev.sh"
echo "Update Vulnrichment data"
"$BASEPATH/update-vulnrich.sh"
echo "Update Exploits data"
"$BASEPATH/update-exploits.sh"

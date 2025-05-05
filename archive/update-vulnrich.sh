#!/bin/sh

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASEPATH="$SCRIPT_DIR"
echo "Using base path: $BASEPATH"

# env
targetdir="$BASEPATH/vulnrichment"
outfile="/opt/epss-db/epss-data/vulnrichment.csv"

# Argument: skip CSV generation?
SKIP_CSV=0
if [ "$1" = "--skip-csv" ]; then
  SKIP_CSV=1
fi

# file pre delete
if [ "$SKIP_CSV" -eq 0 ]; then
  echo "rmfile"
  if [ -e $outfile ]; then
    rm $outfile
    echo "rm"
  fi
fi

# update vulnrichment
echo "---"
echo "Update Vulnrichment reposiotry."
cd $targetdir
git pull

# create CSV data from Vulnrichment JSON
if [ "$SKIP_CSV" -eq 0 ]; then
  echo "---"
  echo "Create import csv file."
  find $targetdir -name "*.json" -exec "$BASEPATH/subprogram/vulnrichUpdate.sh" {} \;
else
  echo "---"
  echo "Skipping CSV creation; using existing $outfile"
fi

# Ensure the CSV file is readable by MySQL (set permissions to 644)
echo "---"
echo "Set permissions for MySQL import"
chmod 644 $outfile

# import CSV data
echo "---"
echo "Import data to mysql"
mysql --defaults-extra-file="$BASEPATH/my.cnf" epssdb -e "load data infile '$outfile' into table richment fields terminated by ',' enclosed by '\"' (cveId, adpCweId, adpSSVCExploitation, adpSSVCAutomatable, adpSSVCTechImpact, adpKEVDateadded, adpKEVRef, adp31Score, adp31Severity, adp31Vector, cna31Score, cna31Severity, cna31VectorString, cna40Score, cna40Severity, cna40Vector);"

# (Optional) Change ownership back to epssuser if needed
#if command -v sudo >/dev/null 2>&1; then
#  sudo chown epssuser:epssuser $outfile
#else
#  chown epssuser:epssuser $outfile
#fi
echo "- finish"

#!/bin/sh

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASEPATH="$(dirname "$SCRIPT_DIR")"
# Note: We're not using BASEPATH in this script, but added for consistency

infile=$1
outfile="/opt/epss-db/epss-data/vulnrichment.csv"

# CVE-ID
cveid=`jq -r '.cveMetadata.cveId // "NULL"' $infile`

# CWE-ID
cweid=`jq -r '.containers.adp[]?.problemTypes[]?.descriptions[]?.cweId' $infile`

# SSVC
ssvcExpl=`jq -r '.containers.adp[]?.metrics[]?.other? | select(.type=="ssvc") | .content?.options[0]?.Exploitation ' $infile`
ssvcAuto=`jq -r '.containers.adp[]?.metrics[]?.other? | select(.type=="ssvc") | .content?.options[1]?.Automatable' $infile`
ssvcTech=`jq -r '.containers.adp[]?.metrics[]?.other? | select(.type=="ssvc") | .content?.options[2]?."Technical Impact"' $infile`

# KEV
kevDate=$(jq -r '.containers.adp[]?.metrics[]?.other? | select(.type == "kev") | .content?.dateAdded' "$infile")
if [ -z "$kevDate" ] ; then
  kevDate="1900-01-01"
fi

kevRef=`jq -r '.containers.adp[]?.metrics[]?.other? | select(.type=="kev") | .content?.reference'  $infile`

# adp.cvssV31
adpV31score=`jq -r '.containers.adp[]?.metrics[]? | select(.cvssV3_1) | .cvssV3_1.baseScore' $infile`
# Fix: quote the variable and use pattern matching instead of -z test for numbers
if [ "$adpV31score" = "" ] || [ "$adpV31score" = "null" ] ; then
  adpV31score="0"
fi

adpV31severity=`jq -r '.containers.adp[]?.metrics[]? | select(.cvssV3_1) | .cvssV3_1.baseSeverity' $infile`
adpV31vector=`jq -r '.containers.adp[]?.metrics[]? | select(.cvssV3_1) | .cvssV3_1.vectorString' $infile`

# cna.cvssV31
cnaV31score=`jq -r '.containers.cna.metrics[]? | select(.cvssV3_1) | .cvssV3_1.baseScore' $infile`
# Fix: quote the variable and use pattern matching instead of -z test for numbers
if [ "$cnaV31score" = "" ] || [ "$cnaV31score" = "null" ] ; then
  cnaV31score="0"
fi
cnaV31severity=`jq -r '.containers.cna.metrics[]? | select(.cvssV3_1) | .cvssV3_1.baseSeverity' $infile`
cnaV31vector=`jq -r '.containers.cna.metrics[]? | select(.cvssV3_1) | .cvssV3_1.vectorString' $infile`

# cna.cvssV40
cnaV40score=`jq -r '.containers.cna.metrics[]? | select(.cvssV4_0) | .cvssV4_0.baseScore' $infile`
# Fix: quote the variable and use pattern matching instead of -z test for numbers
if [ "$cnaV40score" = "" ] || [ "$cnaV40score" = "null" ] ; then
  cnaV40score="0"
fi

cnaV40severity=`jq -r '.containers.cna.metrics[]? | select(.cvssV4_0) | .cvssV4_0.baseSeverity' $infile`
cnaV40vector=`jq -r '.containers.cna.metrics[]? | select(.cvssV4_0) | .cvssV4_0.vectorString' $infile`

# Sanitize all fields to ensure single-line, trimmed, safe output
sanitize() {
  echo "$1" | tr -d '\n\r' | sed 's/^ *//;s/ *$//'
}

cveid=$(sanitize "$cveid")
cweid=$(sanitize "$cweid")
ssvcExpl=$(sanitize "$ssvcExpl")
ssvcAuto=$(sanitize "$ssvcAuto")
ssvcTech=$(sanitize "$ssvcTech")
kevDate=$(sanitize "$kevDate")
kevRef=$(sanitize "$kevRef")
adpV31score=$(sanitize "$adpV31score")
adpV31severity=$(sanitize "$adpV31severity")
adpV31vector=$(sanitize "$adpV31vector")
cnaV31score=$(sanitize "$cnaV31score")
cnaV31severity=$(sanitize "$cnaV31severity")
cnaV31vector=$(sanitize "$cnaV31vector")
cnaV40score=$(sanitize "$cnaV40score")
cnaV40severity=$(sanitize "$cnaV40severity")
cnaV40vector=$(sanitize "$cnaV40vector")

# Ensure numeric fields are valid floats, else set to 0
echo "$adpV31score" | grep -Eq '^[0-9]+(\.[0-9]+)?$' || adpV31score="0"
echo "$cnaV31score" | grep -Eq '^[0-9]+(\.[0-9]+)?$' || cnaV31score="0"
echo "$cnaV40score" | grep -Eq '^[0-9]+(\.[0-9]+)?$' || cnaV40score="0"

# output
echo "\"$cveid\",\"$cweid\",\"$ssvcExpl\",\"$ssvcAuto\",\"$ssvcTech\",\"$kevDate\",\"$kevRef\",\"$adpV31score\",\"$adpV31severity\",\"$adpV31vector\",\"$cnaV31score\",\"$cnaV31severity\",\"$cnaV31vector\",\"$cnaV40score\",\"$cnaV40severity\",\"$cnaV40vector\"" >> $outfile

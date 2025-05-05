#!/bin/bash

# packetstorm-update.sh - Update exploit data from Packet Storm Security
# Using dynamic path detection for portability
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UTILS_DIR="$SCRIPT_DIR/utils"
BASEPATH="$(dirname "$(dirname "$SCRIPT_DIR")")"
TEMP_DIR="/tmp/packetstorm"
MONTHS_TO_FETCH=12  # How many months of archives to process

# Source the database functions
source "$UTILS_DIR/db-functions.sh"
echo "[DEBUG] MYSQL_CONFIG in packetstorm-update.sh is $MYSQL_CONFIG"

echo "=== Updating Packet Storm Data ==="
echo "Using base path: $BASEPATH"

# Create temp directory if it doesn't exist
mkdir -p "$TEMP_DIR"

# Function to download and extract monthly archives
function process_month_archive() {
  local year=$1
  local month=$2
  
  # Format month with leading zero
  month_padded=$(printf "%02d" $month)
  
  # Construct archive URL (Packet Storm archives are named like YYYYMM-exploits.tgz)
  archive_name="${year}${month_padded}-exploits.tgz"
  archive_url="https://dl.packetstormsecurity.net/YYYY/MM/${archive_name}"
  archive_url="${archive_url/YYYY/$year}"
  archive_url="${archive_url/MM/$month_padded}"
  
  echo "Processing archive: $archive_name from $archive_url"
  
  # Download archive if it doesn't exist
  if [ ! -f "$TEMP_DIR/$archive_name" ]; then
    echo "Downloading $archive_name..."
    http_status=$(curl -s -w "%{http_code}" -o "$TEMP_DIR/$archive_name" "$archive_url")
    if [ "$http_status" != "200" ]; then
      echo "Error: Failed to download $archive_url (HTTP $http_status)"
      rm -f "$TEMP_DIR/$archive_name"
      return 1
    fi
    # Check file size
    if [ ! -s "$TEMP_DIR/$archive_name" ]; then
      echo "Error: Downloaded $archive_name is empty."
      rm -f "$TEMP_DIR/$archive_name"
      return 1
    fi
  fi
  
  # Create directory for this month's exploits
  month_dir="$TEMP_DIR/${year}${month_padded}"
  mkdir -p "$month_dir"
  
  # Extract archive
  echo "Extracting $archive_name..."
  if ! tar -xzf "$TEMP_DIR/$archive_name" -C "$month_dir"; then
    echo "Error: Failed to extract $archive_name (not a valid gzip file or corrupted)"
    file "$TEMP_DIR/$archive_name"
    return 1
  fi
  
  # Process each exploit file (typically .txt files with headers)
  find "$month_dir" -type f -name "*.txt" | while read -r exploit_file; do
    # Extract metadata from file headers
    file_id=$(basename "$exploit_file" .txt)
    title=$(grep -m 1 "^Title:" "$exploit_file" | cut -d: -f2- | sed 's/^ //g')
    date=$(grep -m 1 "^Date:" "$exploit_file" | cut -d: -f2- | sed 's/^ //g')
    author=$(grep -m 1 "^Author:" "$exploit_file" | cut -d: -f2- | sed 's/^ //g')
    
    # Convert date to ISO format if possible
    if [[ "$date" =~ ([A-Za-z]+)\ +([0-9]+),\ +([0-9]+) ]]; then
      month_name="${BASH_REMATCH[1]}"
      day="${BASH_REMATCH[2]}"
      year="${BASH_REMATCH[3]}"
      # Convert month name to number
      case "$month_name" in
        January) month_num="01" ;;
        February) month_num="02" ;;
        March) month_num="03" ;;
        April) month_num="04" ;;
        May) month_num="05" ;;
        June) month_num="06" ;;
        July) month_num="07" ;;
        August) month_num="08" ;;
        September) month_num="09" ;;
        October) month_num="10" ;;
        November) month_num="11" ;;
        December) month_num="12" ;;
        *) month_num="01" ;;  # Default if parsing fails
      esac
      date_iso="${year}-${month_num}-$(printf "%02d" "$day")"
    else
      # If date parsing fails, use the archive date
      date_iso="${year}-${month_padded}-01"
    fi
    
    # Extract CVE IDs from the file
    cve_ids=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$exploit_file" | sort -u)
    
    # If we found CVE IDs, process the exploit
    if [ -n "$cve_ids" ]; then
      # Generate URL to the exploit on Packet Storm
      url="https://packetstormsecurity.com/files/${file_id}/"
      
      # Read the first 500 chars as description
      description=$(head -c 500 "$exploit_file" | tr '\n' ' ' | sed 's/"/\\"/g')
      
      # Determine technique from file content keywords
      technique="unknown"
      if grep -qi "remote" "$exploit_file"; then
        technique="remote"
      elif grep -qi "local" "$exploit_file"; then
        technique="local"
      elif grep -qi "dos" "$exploit_file" || grep -qi "denial of service" "$exploit_file"; then
        technique="dos"
      elif grep -qi "overflow" "$exploit_file"; then
        technique="overflow"
      elif grep -qi "injection" "$exploit_file"; then
        technique="injection"
      fi
      
      # Process each CVE ID
      for cve_id in $cve_ids; do
        echo "Adding $cve_id from Packet Storm (ID: $file_id)"
        
        # Insert the exploit record
        insert_exploit "$cve_id" "source_packetstorm" "$file_id" "$url" "$title" "$description" "$date_iso" "$technique"
        
        # Add metadata
        insert_exploit_metadata "$cve_id" "source_packetstorm" "$file_id" "author" "$author"
        insert_exploit_metadata "$cve_id" "source_packetstorm" "$file_id" "file_path" "$exploit_file"
        
        # Add tags
        insert_exploit_tag "$cve_id" "source_packetstorm" "$file_id" "$technique"
        
        # Add additional tags based on content
        if grep -qi "proof of concept" "$exploit_file" || grep -qi "PoC" "$exploit_file"; then
          insert_exploit_tag "$cve_id" "source_packetstorm" "$file_id" "poc"
        fi
        if grep -qi "metasploit" "$exploit_file"; then
          insert_exploit_tag "$cve_id" "source_packetstorm" "$file_id" "metasploit"
        fi
      done
    fi
  done
  
  return 0
}

# Clear existing Packet Storm data
echo "Clearing previous Packet Storm records..."
clear_source_exploits "source_packetstorm"

# Calculate months to fetch based on current date
current_year=$(date +"%Y")
current_month=$(date +"%m")

echo "Fetching $MONTHS_TO_FETCH months of Packet Storm archives..."
for ((i=0; i<MONTHS_TO_FETCH; i++)); do
  # Calculate target month (going backward from current month)
  target_month=$((current_month - i))
  target_year=$current_year
  
  # Handle year boundaries
  while [ $target_month -le 0 ]; do
    target_month=$((target_month + 12))
    target_year=$((target_year - 1))
  done
  
  # Process this month's archive
  process_month_archive $target_year $target_month
done

echo "=== Packet Storm Update Completed ==="

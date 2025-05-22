#!/bin/bash

# db-functions.sh - Shared database functions for exploit sources
# Using dynamic path detection for portability
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASEPATH="$(dirname "$(dirname "$SCRIPT_DIR")")"
MYSQL_CONFIG="$BASEPATH/my.cnf"
echo "[DEBUG] MYSQL_CONFIG is $MYSQL_CONFIG"

# Function to insert an exploit record
# Arguments:
#   $1: cve_id
#   $2: source
#   $3: source_id
#   $4: url
#   $5: title
#   $6: description
#   $7: date_published (YYYY-MM-DD)
#   $8: technique
function insert_exploit() {
  local cve_id="$1"
  local source="$2"
  local source_id="$3"
  local url="$4"
  local title="$5"
  local description="$6"
  local date_published="$7"
  local technique="$8"
  
  # Escape single quotes for SQL
  title=$(echo "$title" | sed "s/'/''/g")
  description=$(echo "$description" | sed "s/'/''/g")
  
  # Insert the exploit record
  mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -e "
  INSERT INTO exploits (cve_id, source, source_id, url, title, description, date_published, technique)
  VALUES ('$cve_id', '$source', '$source_id', '$url', '$title', '$description', '$date_published', '$technique')
  ON DUPLICATE KEY UPDATE
    url = VALUES(url),
    title = VALUES(title),
    description = VALUES(description),
    date_published = VALUES(date_published),
    technique = VALUES(technique),
    updated_at = CURRENT_TIMESTAMP;
  "
  
  return $?
}

# Function to insert a metadata record
# Arguments:
#   $1: cve_id
#   $2: source
#   $3: source_id
#   $4: meta_key
#   $5: meta_value
function insert_exploit_metadata() {
  local cve_id="$1"
  local source="$2"
  local source_id="$3"
  local meta_key="$4"
  local meta_value="$5"
  
  # Escape single quotes for SQL
  meta_value=$(echo "$meta_value" | sed "s/'/''/g")
  
  # Get the exploit_id first
  local exploit_id=$(mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -N -e "
  SELECT id FROM exploits 
  WHERE cve_id = '$cve_id' AND source = '$source' AND source_id = '$source_id'
  LIMIT 1;
  ")
  
  if [ -z "$exploit_id" ]; then
    echo "Error: Cannot find exploit record for $cve_id from $source"
    return 1
  fi
  
  # Insert the metadata
  mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -e "
  INSERT INTO exploit_metadata (exploit_id, meta_key, meta_value)
  VALUES ('$exploit_id', '$meta_key', '$meta_value')
  ON DUPLICATE KEY UPDATE
    meta_value = VALUES(meta_value);
  "
  
  return $?
}

# Function to insert a tag record
# Arguments:
#   $1: cve_id
#   $2: source
#   $3: source_id
#   $4: tag
function insert_exploit_tag() {
  local cve_id="$1"
  local source="$2"
  local source_id="$3"
  local tag="$4"
  
  # Get the exploit_id first
  local exploit_id=$(mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -N -e "
  SELECT id FROM exploits 
  WHERE cve_id = '$cve_id' AND source = '$source' AND source_id = '$source_id'
  LIMIT 1;
  ")
  
  if [ -z "$exploit_id" ]; then
    echo "Error: Cannot find exploit record for $cve_id from $source"
    return 1
  fi
  
  # Insert the tag
  mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -e "
  INSERT IGNORE INTO exploit_tags (exploit_id, tag)
  VALUES ('$exploit_id', '$tag');
  "
  
  return $?
}

# Function to clear all records for a source
# Arguments:
#   $1: source
function clear_source_exploits() {
  local source="$1"
  
  # Get all exploit ids for this source
  local exploit_ids=$(mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -N -e "
  SELECT id FROM exploits WHERE source = \"$source\";
  ")
  
  # Delete from child tables first
  for id in $exploit_ids; do
    mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -e "
    DELETE FROM exploit_metadata WHERE exploit_id = $id;
    DELETE FROM exploit_tags WHERE exploit_id = $id;
    "
  done
  
  # Then delete from main table
  mysql --defaults-file="$MYSQL_CONFIG" -D epssdb -e "
  DELETE FROM exploits WHERE source = \"$source\";
  "
  
  return $?
}

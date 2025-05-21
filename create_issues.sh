#!/bin/bash
REPO="$1"
if [ -z "$REPO" ]; then
  echo "Usage: $0 <github-org-or-username>/<repo>"
  exit 1
fi

ISSUE_FILE="user_stories_issues.txt"

# Split the file on '---' into separate issues
awk 'BEGIN{RS="---"} {print > ("issue_" NR ".txt")}' "$ISSUE_FILE"

for file in issue_*.txt; do
  title=$(grep '^TITLE:' "$file" | sed 's/^TITLE: //')
  body=$(grep '^BODY:' "$file" | sed 's/^BODY: //')
  labels=$(grep '^LABELS:' "$file" | sed 's/^LABELS: //')
  if [ -n "$title" ] && [ -n "$body" ]; then
    echo "Creating issue: $title"
    gh issue create --repo "$REPO" --title "$title" --body "$body" --label "$labels"
  fi
  rm "$file"
done

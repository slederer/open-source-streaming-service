#!/bin/bash
# collect-playback-results.sh — Collect results from browser-use global playback tests
set -euo pipefail

BU_KEY="${BROWSER_USE_API_KEY:-bu_OI6eTrV_qXPQjHFQhKBvtsZbniGE12eXmjlbZlwml5I}"

echo "=== Global Playback Test Results ==="
echo ""

while IFS=: read -r CC SID; do
  [ -z "$CC" ] && continue
  RESP=$(curl -s "https://api.browser-use.com/api/v3/sessions/${SID}" \
    -H "X-Browser-Use-API-Key: ${BU_KEY}")

  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null)
  OUTPUT=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('output','')[:200])" 2>/dev/null)

  printf "%-4s %-12s %s\n" "$CC" "$STATUS" "$OUTPUT"
done < /tmp/browser-use-sessions.txt

echo ""
echo "=== Check Bitmovin Analytics for full data ==="
echo "    https://dashboard.bitmovin.com/analytics"

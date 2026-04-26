#!/bin/bash
# global-playback-test.sh — Test streaming playback from countries worldwide via browser-use.com
# Generates real Bitmovin Analytics impressions from each country
set -euo pipefail

BU_KEY="${BROWSER_USE_API_KEY:-bu_OI6eTrV_qXPQjHFQhKBvtsZbniGE12eXmjlbZlwml5I}"
SITE="https://stream.slederer.com"

# Get a working video (one with a Bitmovin Stream)
VIDEO_ID=$(curl -s "${SITE}/api/videos" | python3 -c "
import sys, json
for v in json.load(sys.stdin)['data']:
    if 'Sintel' in v['title']:
        print(v['id'])
        break
")
PLAYER_URL="${SITE}/player/${VIDEO_ID}"
echo "Testing playback of: ${PLAYER_URL}"
echo ""

# Countries to test from — broad global coverage
COUNTRIES="us de gb fr jp br au in kr sg za mx se nl it es ca ar eg ng ke ae il tr pl ro cz hu no dk fi at ch be pt ie nz cl co pe my th id ph tw hk pk bd vn"

SESSION_IDS=""

for CC in $COUNTRIES; do
  echo -n "Launching ${CC}... "

  RESP=$(curl -s -X POST "https://api.browser-use.com/api/v3/sessions" \
    -H "X-Browser-Use-API-Key: ${BU_KEY}" \
    -H "Content-Type: application/json" \
    -d "{
      \"task\": \"Go to ${PLAYER_URL} and wait for the video player to load and start playing. Wait 15 seconds to let it buffer and play. Then take note of the video quality shown in the player if visible. After 15 seconds, report: 1) Did the video play? 2) How long did it take to start? 3) Any buffering issues? 4) What quality/resolution was shown?\",
      \"proxy_country_code\": \"${CC}\",
      \"enable_recording\": false
    }")

  SID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id','ERROR'))" 2>/dev/null || echo "ERROR")

  if [ "$SID" != "ERROR" ] && [ -n "$SID" ]; then
    echo "OK ($SID)"
    SESSION_IDS="${SESSION_IDS} ${CC}:${SID}"
  else
    echo "FAILED: $(echo "$RESP" | head -c 200)"
  fi

  # Small delay to avoid rate limiting
  sleep 1
done

echo ""
echo "==> All sessions launched!"
echo "    Saving session IDs..."
echo "$SESSION_IDS" | tr ' ' '\n' | grep ':' > /tmp/browser-use-sessions.txt
echo "    Saved to /tmp/browser-use-sessions.txt"
echo ""
echo "    Wait 2-3 minutes for sessions to complete, then run:"
echo "    ./infra/scripts/collect-playback-results.sh"

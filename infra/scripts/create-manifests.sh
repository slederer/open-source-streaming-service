#!/bin/bash
# create-manifests.sh — Create HLS + DASH manifests for completed encodings and update DB
# Usage: ./infra/scripts/create-manifests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a; source "$ROOT_DIR/.env"; set +a
fi

BM="https://api.bitmovin.com/v1"
bm_post() { curl -s -X POST "$BM$1" -H "X-Api-Key:${BITMOVIN_API_KEY}" -H "Content-Type:application/json" -d "$2"; }
bm_get()  { curl -s "$BM$1" -H "X-Api-Key:${BITMOVIN_API_KEY}"; }
jq_id()   { python3 -c "import sys,json; print(json.load(sys.stdin)['data']['result']['id'])"; }

JOBS_FILE="$ROOT_DIR/content/encoding_jobs.txt"
S3_OUTPUT_ID=$(bm_get "/encoding/outputs/s3" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['result']['items'][0]['id'])")
CF_DOMAIN="${CLOUDFRONT_DOMAIN}"
EC2_IP="${EC2_IP:-44.223.127.79}"

echo "S3 Output: $S3_OUTPUT_ID"
echo "CloudFront: $CF_DOMAIN"
echo ""

while IFS='|' read -r ENC_ID SLUG TITLE OUTPUT_PATH; do
  [ -z "$ENC_ID" ] && continue

  # Check encoding status
  STATUS=$(bm_get "/encoding/encodings/${ENC_ID}/status" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['result']['status'])")
  echo "==> $TITLE ($ENC_ID): $STATUS"

  if [ "$STATUS" != "FINISHED" ]; then
    echo "    Skipping — not finished yet"
    continue
  fi

  # Get muxing IDs for manifest creation
  echo "    Creating HLS manifest..."

  # Get all TS muxings (HLS)
  TS_MUXINGS=$(bm_get "/encoding/encodings/${ENC_ID}/muxings/ts" | python3 -c "
import sys, json
items = json.load(sys.stdin)['data']['result']['items']
for m in items:
    mid = m['id']
    sid = m['streams'][0]['streamId']
    # Get output path
    path = m['outputs'][0]['outputPath'] if m.get('outputs') else ''
    print(f'{mid}|{sid}|{path}')
")

  # Get all fMP4 muxings (DASH)
  FMP4_MUXINGS=$(bm_get "/encoding/encodings/${ENC_ID}/muxings/fmp4" | python3 -c "
import sys, json
items = json.load(sys.stdin)['data']['result']['items']
for m in items:
    mid = m['id']
    sid = m['streams'][0]['streamId']
    path = m['outputs'][0]['outputPath'] if m.get('outputs') else ''
    print(f'{mid}|{sid}|{path}')
")

  # Create HLS manifest
  HLS_MANIFEST_ID=$(bm_post "/encoding/manifests/hls" "{
    \"name\": \"${TITLE} HLS\",
    \"manifestName\": \"manifest.m3u8\",
    \"outputs\": [{
      \"outputId\": \"${S3_OUTPUT_ID}\",
      \"outputPath\": \"${OUTPUT_PATH}/\"
    }]
  }" | jq_id)
  echo "    HLS Manifest: $HLS_MANIFEST_ID"

  # Add streams to HLS manifest
  echo "$TS_MUXINGS" | while IFS='|' read -r MUX_ID STREAM_ID MPATH; do
    [ -z "$MUX_ID" ] && continue
    QUALITY=$(echo "$MPATH" | grep -oE '(1080p|720p|480p|360p|aac)')
    if echo "$MPATH" | grep -q "audio"; then
      URI="audio/aac.m3u8"
      bm_post "/encoding/manifests/hls/${HLS_MANIFEST_ID}/media/audio" "{
        \"encodingId\": \"${ENC_ID}\",
        \"streamId\": \"${STREAM_ID}\",
        \"muxingId\": \"${MUX_ID}\",
        \"language\": \"en\",
        \"name\": \"English\",
        \"segmentPath\": \"audio/aac/hls\",
        \"uri\": \"${URI}\",
        \"groupId\": \"audio\"
      }" > /dev/null
    else
      URI="video_${QUALITY}.m3u8"
      bm_post "/encoding/manifests/hls/${HLS_MANIFEST_ID}/media/video" "{
        \"encodingId\": \"${ENC_ID}\",
        \"streamId\": \"${STREAM_ID}\",
        \"muxingId\": \"${MUX_ID}\",
        \"segmentPath\": \"video/${QUALITY}/hls\",
        \"uri\": \"${URI}\"
      }" > /dev/null
    fi
  done

  # Start HLS manifest generation
  bm_post "/encoding/manifests/hls/${HLS_MANIFEST_ID}/start" "{}" > /dev/null
  echo "    HLS manifest generation started"

  # Create DASH manifest
  echo "    Creating DASH manifest..."
  DASH_MANIFEST_ID=$(bm_post "/encoding/manifests/dash" "{
    \"name\": \"${TITLE} DASH\",
    \"manifestName\": \"manifest.mpd\",
    \"outputs\": [{
      \"outputId\": \"${S3_OUTPUT_ID}\",
      \"outputPath\": \"${OUTPUT_PATH}/\"
    }]
  }" | jq_id)
  echo "    DASH Manifest: $DASH_MANIFEST_ID"

  # Add period
  PERIOD_ID=$(bm_post "/encoding/manifests/dash/${DASH_MANIFEST_ID}/periods" "{}" | jq_id)

  # Add video adaptation set
  VIDEO_AS_ID=$(bm_post "/encoding/manifests/dash/${DASH_MANIFEST_ID}/periods/${PERIOD_ID}/adaptationsets/video" "{}" | jq_id)

  # Add audio adaptation set
  AUDIO_AS_ID=$(bm_post "/encoding/manifests/dash/${DASH_MANIFEST_ID}/periods/${PERIOD_ID}/adaptationsets/audio" "{
    \"lang\": \"en\"
  }" | jq_id)

  # Add representations to DASH
  echo "$FMP4_MUXINGS" | while IFS='|' read -r MUX_ID STREAM_ID MPATH; do
    [ -z "$MUX_ID" ] && continue
    if echo "$MPATH" | grep -q "audio"; then
      bm_post "/encoding/manifests/dash/${DASH_MANIFEST_ID}/periods/${PERIOD_ID}/adaptationsets/${AUDIO_AS_ID}/representations/fmp4" "{
        \"encodingId\": \"${ENC_ID}\",
        \"muxingId\": \"${MUX_ID}\",
        \"segmentPath\": \"audio/aac/dash\"
      }" > /dev/null
    else
      QUALITY=$(echo "$MPATH" | grep -oE '(1080p|720p|480p|360p)')
      bm_post "/encoding/manifests/dash/${DASH_MANIFEST_ID}/periods/${PERIOD_ID}/adaptationsets/${VIDEO_AS_ID}/representations/fmp4" "{
        \"encodingId\": \"${ENC_ID}\",
        \"muxingId\": \"${MUX_ID}\",
        \"segmentPath\": \"video/${QUALITY}/dash\"
      }" > /dev/null
    fi
  done

  # Start DASH manifest generation
  bm_post "/encoding/manifests/dash/${DASH_MANIFEST_ID}/start" "{}" > /dev/null
  echo "    DASH manifest generation started"

  # Build CloudFront URLs
  HLS_URL="https://${CF_DOMAIN}/${OUTPUT_PATH}/manifest.m3u8"
  DASH_URL="https://${CF_DOMAIN}/${OUTPUT_PATH}/manifest.mpd"
  echo "    HLS:  $HLS_URL"
  echo "    DASH: $DASH_URL"

  # Update database on EC2
  echo "    Updating database..."
  ssh -i ~/.ssh/oss-streaming-key.pem ec2-user@${EC2_IP} "cd /opt/streaming/app && docker-compose exec -T postgres psql -U streaming -c \"UPDATE videos SET manifest_hls = '${HLS_URL}', manifest_dash = '${DASH_URL}', encoding_job_id = '${ENC_ID}', status = 'ready' WHERE title = '${TITLE}';\"" 2>&1
  echo "    Done!"
  echo ""

done < "$JOBS_FILE"

echo "==> All manifests created and database updated!"

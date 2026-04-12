#!/bin/bash
# encode-from-s3.sh — Create Bitmovin encodings from S3 input files
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

# Reuse existing S3 output
S3_OUTPUT_ID=$(bm_get "/encoding/outputs/s3" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['result']['items'][0]['id'])")
echo "S3 Output: $S3_OUTPUT_ID"

# Create S3 Input
echo "Creating S3 Input..."
S3_INPUT_ID=$(bm_post "/encoding/inputs/s3" "{
  \"name\": \"oss-streaming-input\",
  \"accessKey\": \"${AWS_ACCESS_KEY_ID}\",
  \"secretKey\": \"${AWS_SECRET_ACCESS_KEY}\",
  \"bucketName\": \"${S3_INPUT_BUCKET}\"
}" | jq_id)
echo "S3 Input: $S3_INPUT_ID"

# Reuse latest codec configs
H264_1080=$(bm_get "/encoding/configurations/video/h264?limit=100" | python3 -c "import sys,json; items=json.load(sys.stdin)['data']['result']['items']; print(next(i['id'] for i in items if i.get('name')=='H264 1080p'))")
H264_720=$(bm_get "/encoding/configurations/video/h264?limit=100" | python3 -c "import sys,json; items=json.load(sys.stdin)['data']['result']['items']; print(next(i['id'] for i in items if i.get('name')=='H264 720p'))")
H264_480=$(bm_get "/encoding/configurations/video/h264?limit=100" | python3 -c "import sys,json; items=json.load(sys.stdin)['data']['result']['items']; print(next(i['id'] for i in items if i.get('name')=='H264 480p'))")
H264_360=$(bm_get "/encoding/configurations/video/h264?limit=100" | python3 -c "import sys,json; items=json.load(sys.stdin)['data']['result']['items']; print(next(i['id'] for i in items if i.get('name')=='H264 360p'))")
AAC_128=$(bm_get "/encoding/configurations/audio/aac?limit=100" | python3 -c "import sys,json; items=json.load(sys.stdin)['data']['result']['items']; print(next(i['id'] for i in items if i.get('name')=='AAC 128kbps'))")
echo "Codec configs: H264 1080=$H264_1080, 720=$H264_720, 480=$H264_480, 360=$H264_360, AAC=$AAC_128"

# Videos: title|s3-filename
VIDEOS="Big Buck Bunny|big-buck-bunny.mov
Sintel|sintel.mp4
Tears of Steel|tears-of-steel.mov"

> "$ROOT_DIR/content/encoding_jobs.txt"

echo "$VIDEOS" | while IFS='|' read -r TITLE S3_FILE; do
  [ -z "$TITLE" ] && continue
  SLUG=$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | tr ' :' '-' | tr -cd 'a-z0-9-')
  OUTPUT_PATH="encodings/${SLUG}"

  echo ""
  echo "--- Encoding: $TITLE (from s3://${S3_INPUT_BUCKET}/${S3_FILE}) ---"

  # Create Encoding
  ENC_ID=$(bm_post "/encoding/encodings" "{
    \"name\": \"${TITLE}\",
    \"cloudRegion\": \"AWS_US_EAST_1\"
  }" | jq_id)
  echo "    Encoding: $ENC_ID"

  # Video streams at each quality
  for PAIR in "1080p|$H264_1080" "720p|$H264_720" "480p|$H264_480" "360p|$H264_360"; do
    QUALITY="${PAIR%%|*}"
    CODEC_ID="${PAIR##*|}"

    STREAM_ID=$(bm_post "/encoding/encodings/${ENC_ID}/streams" "{
      \"codecConfigId\": \"${CODEC_ID}\",
      \"inputStreams\": [{
        \"inputId\": \"${S3_INPUT_ID}\",
        \"inputPath\": \"/${S3_FILE}\",
        \"selectionMode\": \"AUTO\"
      }]
    }" | jq_id)

    # fMP4 for DASH
    bm_post "/encoding/encodings/${ENC_ID}/muxings/fmp4" "{
      \"streams\": [{\"streamId\": \"${STREAM_ID}\"}],
      \"outputs\": [{\"outputId\": \"${S3_OUTPUT_ID}\", \"outputPath\": \"${OUTPUT_PATH}/video/${QUALITY}/dash\"}],
      \"segmentLength\": 4
    }" > /dev/null

    # TS for HLS
    bm_post "/encoding/encodings/${ENC_ID}/muxings/ts" "{
      \"streams\": [{\"streamId\": \"${STREAM_ID}\"}],
      \"outputs\": [{\"outputId\": \"${S3_OUTPUT_ID}\", \"outputPath\": \"${OUTPUT_PATH}/video/${QUALITY}/hls\"}],
      \"segmentLength\": 4
    }" > /dev/null

    echo "    Video ${QUALITY}: $STREAM_ID"
  done

  # Audio stream
  AUDIO_ID=$(bm_post "/encoding/encodings/${ENC_ID}/streams" "{
    \"codecConfigId\": \"${AAC_128}\",
    \"inputStreams\": [{
      \"inputId\": \"${S3_INPUT_ID}\",
      \"inputPath\": \"/${S3_FILE}\",
      \"selectionMode\": \"AUTO\"
    }]
  }" | jq_id)

  bm_post "/encoding/encodings/${ENC_ID}/muxings/fmp4" "{
    \"streams\": [{\"streamId\": \"${AUDIO_ID}\"}],
    \"outputs\": [{\"outputId\": \"${S3_OUTPUT_ID}\", \"outputPath\": \"${OUTPUT_PATH}/audio/aac/dash\"}],
    \"segmentLength\": 4
  }" > /dev/null

  bm_post "/encoding/encodings/${ENC_ID}/muxings/ts" "{
    \"streams\": [{\"streamId\": \"${AUDIO_ID}\"}],
    \"outputs\": [{\"outputId\": \"${S3_OUTPUT_ID}\", \"outputPath\": \"${OUTPUT_PATH}/audio/aac/hls\"}],
    \"segmentLength\": 4
  }" > /dev/null

  echo "    Audio: $AUDIO_ID"

  # Start
  bm_post "/encoding/encodings/${ENC_ID}/start" "{}" > /dev/null
  echo "    STARTED: $ENC_ID"

  echo "${ENC_ID}|${SLUG}|${TITLE}|${OUTPUT_PATH}" >> "$ROOT_DIR/content/encoding_jobs.txt"
done

echo ""
echo "==> All encoding jobs started from S3!"
echo "    Monitor: https://dashboard.bitmovin.com/encoding/encodings"

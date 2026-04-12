#!/bin/bash
# encode.sh — Create Bitmovin VOD encoding jobs for all catalog titles
# Usage: ./infra/scripts/encode.sh
# Requires: BITMOVIN_API_KEY, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY in .env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load env
if [ -f "$ROOT_DIR/.env" ]; then
  set -a; source "$ROOT_DIR/.env"; set +a
fi

BM="https://api.bitmovin.com/v1"
AUTH="-H X-Api-Key:${BITMOVIN_API_KEY}"

bm_post() { curl -s -X POST "$BM$1" -H "X-Api-Key:${BITMOVIN_API_KEY}" -H "Content-Type:application/json" -d "$2"; }
bm_get()  { curl -s "$BM$1" -H "X-Api-Key:${BITMOVIN_API_KEY}"; }
jq_id()   { python3 -c "import sys,json; print(json.load(sys.stdin)['data']['result']['id'])"; }
jq_check(){ python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('result',{}).get('id','ERROR: '+json.dumps(d)))"; }

echo "==> Step 1: Create or reuse S3 Output"
# Check if output already exists
EXISTING_OUTPUT=$(bm_get "/encoding/outputs/s3" | python3 -c "import sys,json; items=json.load(sys.stdin)['data']['result']['items']; print(items[0]['id'] if items else '')" 2>/dev/null)
if [ -n "$EXISTING_OUTPUT" ]; then
  S3_OUTPUT_ID="$EXISTING_OUTPUT"
  echo "    Reusing S3 Output: $S3_OUTPUT_ID"
else
  S3_OUTPUT_ID=$(bm_post "/encoding/outputs/s3" "{
    \"name\": \"oss-streaming-output\",
    \"accessKey\": \"${AWS_ACCESS_KEY_ID}\",
    \"secretKey\": \"${AWS_SECRET_ACCESS_KEY}\",
    \"bucketName\": \"${S3_OUTPUT_BUCKET}\"
  }" | jq_check)
  echo "    Created S3 Output: $S3_OUTPUT_ID"
fi

echo "==> Step 2: Create codec configurations"

create_or_find_codec() {
  local TYPE="$1" NAME="$2" BODY="$3"
  # Just create — Bitmovin allows duplicates, and we need the ID
  bm_post "/encoding/configurations/${TYPE}" "$BODY" | jq_check
}

H264_1080=$(create_or_find_codec "video/h264" "H264 1080p" '{
  "name": "H264 1080p", "height": 1080, "bitrate": 4800000, "profile": "HIGH", "preset": "VOD_STANDARD"
}')
echo "    H264 1080p: $H264_1080"

H264_720=$(create_or_find_codec "video/h264" "H264 720p" '{
  "name": "H264 720p", "height": 720, "bitrate": 2400000, "profile": "HIGH", "preset": "VOD_STANDARD"
}')
echo "    H264 720p: $H264_720"

H264_480=$(create_or_find_codec "video/h264" "H264 480p" '{
  "name": "H264 480p", "height": 480, "bitrate": 1200000, "profile": "MAIN", "preset": "VOD_STANDARD"
}')
echo "    H264 480p: $H264_480"

H264_360=$(create_or_find_codec "video/h264" "H264 360p" '{
  "name": "H264 360p", "height": 360, "bitrate": 800000, "profile": "MAIN", "preset": "VOD_STANDARD"
}')
echo "    H264 360p: $H264_360"

AAC_128=$(create_or_find_codec "audio/aac" "AAC 128kbps" '{
  "name": "AAC 128kbps", "bitrate": 128000, "rate": 48000
}')
echo "    AAC 128k: $AAC_128"

echo "==> Step 3: Encode each video"

# Videos with direct download URLs (title|url pairs)
VIDEOS="Big Buck Bunny|https://download.blender.org/demo/movies/BBB/bbb_sunflower_1080p_30fps_normal.mp4
Sintel|https://download.blender.org/demo/movies/Sintel.2010.1080p.mkv
Tears of Steel|https://download.blender.org/demo/movies/ToS/tears_of_steel_1080p.mov
Elephants Dream|https://download.blender.org/demo/movies/ED/elephantsdream-1080-stereo.avi"

encode_video() {
  local TITLE="$1"
  local SOURCE_URL="$2"
  local SLUG=$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | tr ' :' '-' | tr -cd 'a-z0-9-')
  local OUTPUT_PATH="encodings/${SLUG}"

  echo ""
  echo "--- Encoding: $TITLE ---"
  echo "    Source: $SOURCE_URL"
  echo "    Output: s3://${S3_OUTPUT_BUCKET}/${OUTPUT_PATH}/"

  # Parse host and path from URL
  local HOST=$(echo "$SOURCE_URL" | sed 's|https\?://||' | cut -d/ -f1)
  local PATH_PART="/$(echo "$SOURCE_URL" | sed 's|https\?://[^/]*/||')"

  # Create HTTP Input for this source
  local INPUT_ID=$(bm_post "/encoding/inputs/http" "{
    \"name\": \"source-${SLUG}\",
    \"host\": \"${HOST}\"
  }" | jq_check)
  echo "    Input: $INPUT_ID"

  # Create Encoding
  local ENC_ID=$(bm_post "/encoding/encodings" "{
    \"name\": \"${TITLE}\",
    \"cloudRegion\": \"AWS_US_EAST_1\"
  }" | jq_check)
  echo "    Encoding: $ENC_ID"

  # Create input stream reference (used by all streams)
  # Video streams at different qualities
  for CODEC_NAME in "1080p:$H264_1080" "720p:$H264_720" "480p:$H264_480" "360p:$H264_360"; do
    local QUALITY="${CODEC_NAME%%:*}"
    local CODEC_ID="${CODEC_NAME##*:}"

    local STREAM_ID=$(bm_post "/encoding/encodings/${ENC_ID}/streams" "{
      \"codecConfigId\": \"${CODEC_ID}\",
      \"inputStreams\": [{
        \"inputId\": \"${INPUT_ID}\",
        \"inputPath\": \"${PATH_PART}\",
        \"selectionMode\": \"AUTO\"
      }]
    }" | jq_check)

    # fMP4 muxing for DASH
    bm_post "/encoding/encodings/${ENC_ID}/muxings/fmp4" "{
      \"streams\": [{\"streamId\": \"${STREAM_ID}\"}],
      \"outputs\": [{
        \"outputId\": \"${S3_OUTPUT_ID}\",
        \"outputPath\": \"${OUTPUT_PATH}/video/${QUALITY}/dash\"
      }],
      \"segmentLength\": 4
    }" > /dev/null

    # TS muxing for HLS
    bm_post "/encoding/encodings/${ENC_ID}/muxings/ts" "{
      \"streams\": [{\"streamId\": \"${STREAM_ID}\"}],
      \"outputs\": [{
        \"outputId\": \"${S3_OUTPUT_ID}\",
        \"outputPath\": \"${OUTPUT_PATH}/video/${QUALITY}/hls\"
      }],
      \"segmentLength\": 4
    }" > /dev/null

    echo "    Stream ${QUALITY}: $STREAM_ID"
  done

  # Audio stream
  local AUDIO_STREAM_ID=$(bm_post "/encoding/encodings/${ENC_ID}/streams" "{
    \"codecConfigId\": \"${AAC_128}\",
    \"inputStreams\": [{
      \"inputId\": \"${INPUT_ID}\",
      \"inputPath\": \"${PATH_PART}\",
      \"selectionMode\": \"AUTO\"
    }]
  }" | jq_check)

  bm_post "/encoding/encodings/${ENC_ID}/muxings/fmp4" "{
    \"streams\": [{\"streamId\": \"${AUDIO_STREAM_ID}\"}],
    \"outputs\": [{
      \"outputId\": \"${S3_OUTPUT_ID}\",
      \"outputPath\": \"${OUTPUT_PATH}/audio/aac/dash\"
    }],
    \"segmentLength\": 4
  }" > /dev/null

  bm_post "/encoding/encodings/${ENC_ID}/muxings/ts" "{
    \"streams\": [{\"streamId\": \"${AUDIO_STREAM_ID}\"}],
    \"outputs\": [{
      \"outputId\": \"${S3_OUTPUT_ID}\",
      \"outputPath\": \"${OUTPUT_PATH}/audio/aac/hls\"
    }],
    \"segmentLength\": 4
  }" > /dev/null

  echo "    Audio stream: $AUDIO_STREAM_ID"

  # Start encoding
  bm_post "/encoding/encodings/${ENC_ID}/start" "{}" > /dev/null
  echo "    STARTED encoding $ENC_ID"
  echo "    Dashboard: https://dashboard.bitmovin.com/encoding/encodings/${ENC_ID}"

  # Store encoding ID for later manifest generation and DB update
  echo "${ENC_ID}|${SLUG}|${TITLE}|${OUTPUT_PATH}" >> "$ROOT_DIR/content/encoding_jobs.txt"
}

# Clear previous jobs file
> "$ROOT_DIR/content/encoding_jobs.txt"

echo "$VIDEOS" | while IFS='|' read -r TITLE URL; do
  [ -z "$TITLE" ] && continue
  encode_video "$TITLE" "$URL"
done

echo ""
echo "==> All encoding jobs started!"
echo "    Monitor at: https://dashboard.bitmovin.com/encoding/encodings"
echo "    Job IDs saved to: content/encoding_jobs.txt"
echo ""
echo "    Once encodings finish, run: ./infra/scripts/create-manifests.sh"

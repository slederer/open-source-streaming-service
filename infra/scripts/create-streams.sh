#!/bin/bash
# create-streams.sh — Create Bitmovin Streams for all catalog titles
# Streams API handles encoding + hosting + CDN automatically — much simpler than raw Encoding API
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

BM_KEY="${BITMOVIN_API_KEY:-3f87a021-d050-46a1-b9bb-7db349c172b9}"

# Catalog: title|assetUrl|posterUrl
# Using TMDB / IMDb poster CDNs (more reliable than Wikipedia)
CATALOG='Big Buck Bunny|https://download.blender.org/peach/bigbuckbunny_movies/big_buck_bunny_1080p_h264.mov|https://image.tmdb.org/t/p/w500/kOVEVeg59E0wsnXmF9nrh6OmWII.jpg
Sintel|https://download.blender.org/durian/movies/Sintel.2010.1080p.mkv|https://image.tmdb.org/t/p/w500/kzvJjiLqAYLRQiu1ZjmQmBlFXGj.jpg
Tears of Steel|https://download.blender.org/demo/movies/ToS/ToS-4k-1920.mov|https://image.tmdb.org/t/p/w500/1JXGfVUDnZ9xPD8gxNVYl6YaWyV.jpg
Elephants Dream|https://archive.org/download/ElephantsDream/ed_1024_512kb.mp4|https://image.tmdb.org/t/p/w500/xdGxaCbfzZ3yoQx1iXvNcGGbNbF.jpg
Spring|https://media.xiph.org/video/derf/y4m/spring_1080p.y4m|https://image.tmdb.org/t/p/w500/2e4TNSUO6mz09j9Mv2D5NmcwNHx.jpg
Sprite Fright|https://studio.blender.org/download-source/sprite-fright/sprite_fright_1080p.mp4|https://image.tmdb.org/t/p/w500/jvfpmeK3nxB7e05HPSy0MX1cCVh.jpg
Agent 327|https://download.blender.org/agent-327/barbershop/Agent-327-Operation_Barbershop_h264.mp4|https://image.tmdb.org/t/p/w500/3ryoLRcJcdLmn0ghx0GCsHjwJom.jpg
Night of the Living Dead|https://archive.org/download/night_of_the_living_dead/night_of_the_living_dead.mp4|https://image.tmdb.org/t/p/w500/wxUEpY2N5tQJlRVeEWeZfGaifhy.jpg
Metropolis|https://archive.org/download/Metropolis1927/Metropolis.mp4|https://image.tmdb.org/t/p/w500/kE2jM1DMGT2I1GQktKqbfHvAcbC.jpg
City Lights|https://archive.org/download/CC_1931_02_01_CityLights/CC_1931_02_01_CityLights.mp4|https://image.tmdb.org/t/p/w500/bXNvzjULc9jrOVhGfjcc64uKZmZ.jpg
The Phantom Carriage|https://archive.org/download/ThePhantomCarriage/ThePhantomCarriage.mp4|https://image.tmdb.org/t/p/w500/azHCOEZGa0YrV3SbBa2PgcZ7Jqb.jpg
ISS Earth Time-Lapse 4K|https://images-assets.nasa.gov/video/iss064e036648/iss064e036648~orig.mp4|https://image.tmdb.org/t/p/w500/yhDgT87E9Hpz0UVVjJiSw1dH4Is.jpg'

> "$ROOT_DIR/content/streams.txt"

echo "$CATALOG" | while IFS='|' read -r TITLE ASSET_URL POSTER_URL; do
  [ -z "$TITLE" ] && continue

  # Verify asset URL works
  HTTP_CODE=$(curl -sI -w "%{http_code}" -o /dev/null -L "$ASSET_URL" --max-time 10 || echo "000")
  if [ "$HTTP_CODE" != "200" ]; then
    echo "SKIP $TITLE: asset URL returned $HTTP_CODE — $ASSET_URL"
    continue
  fi

  echo "Creating stream: $TITLE"
  RESP=$(curl -s -X POST "https://api.bitmovin.com/v1/streams/video" \
    -H "X-Api-Key:${BM_KEY}" \
    -H "Content-Type:application/json" \
    -d "{
      \"title\": \"${TITLE}\",
      \"assetUrl\": \"${ASSET_URL}\",
      \"posterUrl\": \"${POSTER_URL}\"
    }")

  STREAM_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('result',{}).get('id',''))" 2>/dev/null)

  if [ -n "$STREAM_ID" ]; then
    echo "  OK: $STREAM_ID"
    echo "${STREAM_ID}|${TITLE}" >> "$ROOT_DIR/content/streams.txt"
  else
    echo "  FAIL: $(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('message','unknown'))" 2>/dev/null)"
  fi
done

echo ""
echo "==> Streams created. IDs saved to content/streams.txt"

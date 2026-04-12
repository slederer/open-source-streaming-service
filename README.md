# Open Source Streaming Service

A full-stack demo OTT streaming service built with the **Bitmovin** product suite on **AWS**, featuring VOD + Live streaming, server-side ad insertion (SSAI), DRM, and AI-powered content analytics.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Web (Next.js)│     │  iOS (SwiftUI)│     │ Vidaa (HTML5 TV)│
└──────┬───────┘     └──────┬───────┘     └──────┬──────────┘
       │                    │                     │
       └────────────────────┼─────────────────────┘
                            │
                    ┌───────▼────────┐
                    │   Go Backend   │
                    │  (chi + sqlx)  │
                    └───────┬────────┘
                            │
              ┌─────────────┼──────────────┐
              │             │              │
     ┌────────▼───┐  ┌─────▼─────┐  ┌─────▼──────┐
     │  Postgres  │  │ Bitmovin  │  │    AWS     │
     │            │  │ Encoding  │  │ S3 + CF +  │
     │            │  │ Player    │  │ MediaTailor│
     │            │  │ Analytics │  │            │
     └────────────┘  └───────────┘  └────────────┘
```

## Products Used

| Product | Purpose |
|---------|---------|
| **Bitmovin VOD Encoding** | Per-title adaptive bitrate encoding (HLS + DASH) with SCTE-35 markers |
| **Bitmovin Live Encoding** | 24/7 live channel from RTMP input |
| **Bitmovin Player** | Web, iOS, and Vidaa smart TV playback |
| **Bitmovin Analytics** | Player-side observability across all platforms |
| **Bitmovin AI Content Analytics** | Auto-generated thumbnails and scene descriptions |
| **AWS MediaTailor** | Server-side ad insertion (SSAI) for VOD and Live |
| **PallyCon DRM** | Widevine (Chrome/Vidaa) + FairPlay (iOS/Safari) encryption |

## Content Catalog

12 freely-licensed titles (all commercially redistributable):

- **Blender Films** (CC-BY 4.0): Big Buck Bunny, Sintel, Tears of Steel, Elephants Dream, Spring, Sprite Fright, Agent 327
- **Internet Archive** (Public Domain): Night of the Living Dead, Metropolis, City Lights
- **Library of Congress** (Public Domain): The Phantom Carriage
- **NASA** (Public Domain): ISS Earth Time-Lapse 4K

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Bitmovin account (API key + Player key)
- AWS account (for S3, CloudFront, MediaTailor)
- PallyCon account (optional, for DRM)

### Local Development

```bash
# 1. Clone and configure
git clone https://github.com/slederer/open-source-streaming-service.git
cd open-source-streaming-service
cp .env.example .env
# Edit .env with your API keys

# 2. Start all services
docker compose up -d

# 3. Ingest catalog (requires Bitmovin API key + AWS credentials)
docker compose exec backend ingest --catalog /content/catalog.json

# 4. Open browser
open http://localhost
```

### Running Tests

```bash
# Go backend tests
cd backend && go test ./...

# Next.js web tests
cd web && npm test

# Vidaa HTML5 tests
cd vidaa && npx vitest run
```

### Deploy to AWS

```bash
# 1. Provision infrastructure
cd infra/terraform
terraform init
terraform apply -var="ec2_key_pair_name=your-key"

# 2. Deploy to EC2
./infra/scripts/deploy.sh <EC2_IP>
```

## Project Structure

```
├── backend/          # Go API server (chi + sqlx + Postgres)
│   ├── cmd/server/   # API entrypoint
│   ├── cmd/ingest/   # Content ingestion CLI
│   └── internal/     # handlers, store, bitmovin, pallycon, mediatailor, ads
├── web/              # Next.js frontend (React + Tailwind)
├── ios/              # SwiftUI iOS app
├── vidaa/            # Vanilla HTML5 TV app (Vidaa/Tizen)
├── infra/            # Terraform, Nginx, systemd, deploy scripts
├── content/          # catalog.json + live playlist
└── docker-compose.yml
```

## License

The streaming service code is open source. Content licenses vary per title — see `content/catalog.json` for individual licensing.

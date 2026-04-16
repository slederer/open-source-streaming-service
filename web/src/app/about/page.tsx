import Link from "next/link";

export const metadata = {
  title: "About — OSStream",
  description: "How this streaming service was built, the hurdles we hit, and what Bitmovin can do to be more AI-native.",
};

export default function AboutPage() {
  return (
    <div className="max-w-4xl mx-auto py-8">
      <h1 className="text-4xl font-bold text-white mb-2">Behind the Build</h1>
      <p className="text-gray-400 mb-10">
        A full-stack OTT streaming service built in one session with Claude Code.{" "}
        <Link
          href="https://github.com/slederer/open-source-streaming-service"
          className="text-blue-400 hover:text-blue-300 underline"
        >
          Source on GitHub
        </Link>
        .
      </p>

      {/* ==== What we built ==== */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-white mb-4">What we built</h2>
        <div className="space-y-4 text-gray-300 leading-relaxed">
          <p>
            A complete OTT streaming service showcasing the Bitmovin product
            stack running on AWS: Go backend with chi/sqlx/Postgres, Next.js 16
            web frontend, SwiftUI iOS app, vanilla-JS Vidaa smart TV app,
            Terraform infrastructure for EC2 + S3 + CloudFront, Google OAuth
            login, DoveRunner (PallyCon) DRM hooks, MediaTailor SSAI hooks,
            Docker Compose deployment, 44+ tests across Go and Vitest — all
            live at{" "}
            <Link href="/" className="text-blue-400">
              stream.slederer.com
            </Link>{" "}
            behind Cloudflare-managed HTTPS.
          </p>
        </div>
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Commits" value="50+" />
          <StatCard label="Tests passing" value="44" />
          <StatCard label="Titles in catalog" value="12" />
          <StatCard label="Client platforms" value="3" />
        </div>
      </section>

      {/* ==== Stack ==== */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-white mb-4">Stack</h2>
        <div className="grid md:grid-cols-2 gap-4 text-sm">
          <StackGroup
            title="Bitmovin"
            items={[
              "Player (web + iOS + Vidaa)",
              "Streams API (encoding + hosting + thumbnails)",
              "VOD Encoding API (direct)",
              "Live Encoding API (planned)",
              "Analytics / Observability",
              "AI Content Analytics (planned)",
            ]}
          />
          <StackGroup
            title="AWS"
            items={[
              "EC2 t3.small (Docker host)",
              "S3: input / output / thumbnails",
              "CloudFront CDN",
              "MediaTailor (SSAI, planned)",
              "IAM roles + dedicated encoder user",
              "Elastic IP + security groups",
            ]}
          />
          <StackGroup
            title="App"
            items={[
              "Go 1.26 (chi router, sqlx, lib/pq)",
              "Next.js 16 (App Router, Tailwind)",
              "SwiftUI (iOS)",
              "Vanilla JS (Vidaa HTML5)",
              "Postgres 16",
              "Docker Compose + Nginx",
            ]}
          />
          <StackGroup
            title="Auth, DRM & Delivery"
            items={[
              "Google OAuth + sessions",
              "DoveRunner (PallyCon) Widevine + FairPlay",
              "Cloudflare DNS + TLS",
              "stream.slederer.com",
            ]}
          />
        </div>
      </section>

      {/* ==== Hurdles ==== */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-white mb-4">
          Hurdles we hit (in order)
        </h2>
        <div className="space-y-4">
          <Hurdle
            n={1}
            title="AWS vCPU limit (16)"
            detail="All 16 on-demand standard vCPUs were already allocated to other projects in the account. Had to stop streaming-finder to free 2 vCPUs for the new EC2."
          />
          <Hurdle
            n={2}
            title="MediaTailor not in the Terraform AWS provider"
            detail="aws_media_tailor_playback_configuration wasn't available in our provider version. Removed it from Terraform; will be created via AWS CLI separately."
          />
          <Hurdle
            n={3}
            title="t3.small OOM during parallel Docker builds"
            detail="Building Go and Next.js containers simultaneously on 2 GB of RAM locked up the instance and SSH stopped responding. Added 2 GB swap and rebuilt images sequentially."
          />
          <Hurdle
            n={4}
            title="Docker on EC2 missing compose + buildx"
            detail="Amazon Linux 2023's docker (v25) shipped without the compose plugin and without buildx. Installed both manually before docker-compose up would work."
          />
          <Hurdle
            n={5}
            title="Next.js NEXT_PUBLIC_* vars must be baked at build time"
            detail="Tried setting them at runtime — browser got 'localhost refused to connect' because the JS bundle had hardcoded localhost. Fixed by using ARG in Dockerfile and passing --build-arg, then switching client code to use relative URLs through nginx."
          />
          <Hurdle
            n={6}
            title="Bitmovin Encoding fails at 90% — no actionable error"
            detail="Every encoding job completed transcoding (hit 90%) then failed to write output to S3 with: 'Problem with output configuration. Check your AWS S3 or Google GCS bucket configuration and permissions.' We tried root creds, dedicated IAM user with AmazonS3FullAccess, removed SSE encryption, removed public-access-block, used Generic S3 output with explicit endpoints. All failed. Opened a support ticket."
            severity="blocker"
          />
          <Hurdle
            n={7}
            title="Bitmovin encoder can't HTTP-download from Blender"
            detail="The HTTP Input resource validated fine, but encodings failed with 'Download of input file failed.' We had to download ~2 GB of masters locally and re-upload to our own S3 input bucket first."
          />
          <Hurdle
            n={8}
            title="Source URLs for 8 of 12 titles are blocked"
            detail="Archive.org returned 403/503 (rate-limited from EC2 IPs), NASA returned 403, Blender studio 404'd. Only the main Blender download server with their Peach/Durian/Mango URLs worked reliably. Result: only Big Buck Bunny, Sintel, Tears of Steel, and Elephants Dream have real content."
          />
          <Hurdle
            n={9}
            title="Wikipedia poster hotlinking rate-limited (429)"
            detail="Hardcoded Wikipedia poster URLs returned 429 Too Many Requests when served from browsers. Replaced with Bitmovin Streams' auto-generated thumbnail URLs where available and with per-title HSL gradient placeholders for the rest."
          />
          <Hurdle
            n={10}
            title="DRM tokens returned for unencrypted streams"
            detail="The playback endpoint returned DRM license URLs + tokens for all videos, including public test streams. The Bitmovin Player then failed trying to acquire a license for content that wasn't actually encrypted. Fixed by only returning DRM config when both encoding_job_id AND drm_content_id are set (meaning the video went through real DRM encoding)."
          />
          <Hurdle
            n={11}
            title="Bitmovin Player UI module separate from the core"
            detail="Importing bitmovin-player gives you a headless player — no play button, no seek bar. The UI lives in bitmovinplayer-ui.js + bitmovinplayer-ui.css and must be explicitly imported and wired via UIFactory.buildDefaultUI(player). Easy to miss."
          />
        </div>
      </section>

      {/* ==== AI-native feedback ==== */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-white mb-4">
          What Bitmovin could do better for developers & AI agents
        </h2>
        <p className="text-gray-300 mb-6 leading-relaxed">
          Based on the specific friction encountered while building this in a
          single agent session. Grouped by leverage — the first item alone
          would have saved hours.
        </p>

        <h3 className="text-lg font-semibold text-blue-400 mt-8 mb-3">
          Showstoppers
        </h3>
        <Feedback
          n={1}
          title="Ship an official Bitmovin MCP server"
          body="Model Context Protocol servers expose tools to agents like Claude directly. A single mcp__bitmovin__encode(url) or mcp__bitmovin__create_stream(url, drm_config) tool replaces the 200+ lines of bash wrapping curl calls I wrote today. This is the single highest-leverage fix for agent usability."
        />
        <Feedback
          n={2}
          title="Surface the real underlying error"
          body='"Problem with output configuration" without showing what S3 returned made me blind-guess fixes for hours. Return the actual AWS error code (AccessDenied vs NoSuchBucket vs PermissionDenied) plus the full request path and the HTTP status from S3.'
        />
        <Feedback
          n={3}
          title="Add direct URL input to Encoding API"
          body="Streams API accepts assetUrl and downloads; Encoding API's HTTP Input requires a pre-verified host and sometimes silently rejects public URLs. I had to re-host 2 GB of masters on my own S3 because the encoder couldn't download from download.blender.org. Make 'encode from URL' first-class in Encoding too."
        />
        <Feedback
          n={4}
          title="Make account/trial limits visible in API responses"
          body='Jobs queued, ran, and failed silently. A field like "accountLimit": "trial: 5_encodings_per_day_exceeded" in the status response would have saved debugging time.'
        />

        <h3 className="text-lg font-semibold text-blue-400 mt-8 mb-3">
          Major ergonomics
        </h3>
        <Feedback
          n={5}
          title="Make Encoding Templates the default path in docs"
          body="Templates exist and are excellent, but the quickstart still shows the imperative ~15-step API choreography (Input → Output → CodecConfig × N → Encoding → Stream × N → Muxing × 2N → Manifest × 2 → media × N → start). Templates reduce that to one POST of a YAML doc. Agents and humans both benefit from having the declarative path front and center."
        />
        <Feedback
          n={6}
          title="One-call encode endpoint"
          body="A POST /v1/encoding/quick-encode that takes { input_url, output_bucket, drm?, ssai? } and returns { manifest_hls, manifest_dash } would replace the entire encoding pipeline for 90% of use cases."
        />
        <Feedback
          n={7}
          title="Publish a proper OpenAPI 3 spec with examples"
          body="I hand-crafted every request. A complete spec with example payloads would let any agent generate a typed client in any language in seconds. Include the common pitfalls as docstrings."
        />
        <Feedback
          n={8}
          title="Idempotent resource creation"
          body='Re-running my encoding script created duplicate codec configs (I had 10+ "H264 1080p" entries after 3 runs). Support PUT /configurations/video/h264?name=H264+1080p with upsert semantics, or let POST return the existing resource when a unique name collides.'
        />
        <Feedback
          n={9}
          title="Let us retry a failed encoding"
          body="When encoding fails, the resource is terminal — you can't change its output config and retry. You have to recreate the encoding with all its streams, muxings, and manifests from scratch. Add POST /encodings/{id}/retry or allow patching output config on a FAILED encoding."
        />

        <h3 className="text-lg font-semibold text-blue-400 mt-8 mb-3">
          Streams API & Player
        </h3>
        <Feedback
          n={10}
          title="Return poster URL in Streams API response"
          body="I had to curl /{id}/embed and regex out og:image to get the poster URL. Add posterUrl and thumbnailSpriteUrl to GET /streams/video/{id}."
        />
        <Feedback
          n={11}
          title="Expose a clean single-frame poster URL"
          body="Only thumbnails-5_0.png (a sprite sheet) is publicly accessible. Paths like cover.jpg and poster.jpg all 403. Serve a single large poster at /streams/{id}/poster.jpg."
        />
        <Feedback
          n={12}
          title="Make Player UI default on"
          body={'Importing "bitmovin-player" should give you a working player with UI — not a headless component that requires separately importing bitmovinplayer-ui.js, the CSS, and calling UIFactory.buildDefaultUI(player). Keep the current setup for advanced users but have the default import include the UI.'}
        />

        <h3 className="text-lg font-semibold text-blue-400 mt-8 mb-3">
          Operational
        </h3>
        <Feedback
          n={13}
          title="HMAC-signed webhooks"
          body='Bitmovin encoding webhooks arrive at the customer backend with no signature. Anyone who knows the URL can POST a fake "FINISHED" event and mark videos ready. Add an X-Bitmovin-Signature header computed over the body with a per-account secret.'
        />
        <Feedback
          n={14}
          title="SDK clients with built-in retry/backoff"
          body="The Go SDK uses a raw http.Client with no retry logic. Transient 500s from the API mean the whole encoding orchestration script breaks. Ship SDKs with exponential backoff + jitter + Retry-After respect by default."
        />

        <div className="mt-10 p-5 bg-blue-900/30 border border-blue-700 rounded-lg">
          <h3 className="text-lg font-semibold text-white mb-2">
            One-line TL;DR
          </h3>
          <p className="text-gray-200">
            Ship an MCP server and make declarative Encoding Templates (or a
            single <code className="bg-black/40 px-1 rounded">POST /encode</code>{" "}
            endpoint) the default path. Agents don&apos;t want to orchestrate
            15 sequential API calls; they want to describe the desired output
            and get a manifest URL back.
          </p>
        </div>
      </section>

      {/* ==== Credits ==== */}
      <section className="mb-12 pt-8 border-t border-gray-800">
        <h2 className="text-xl font-bold text-white mb-3">Credits</h2>
        <p className="text-gray-400 text-sm leading-relaxed">
          Content licenses: Blender Foundation films (CC-BY 4.0), Internet
          Archive public-domain features, Library of Congress National
          Screening Room, NASA. Built with Bitmovin, AWS, Cloudflare, Next.js,
          Go, Docker, Terraform. Developed with Claude Code.
        </p>
      </section>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-gray-900 rounded-lg p-4 text-center border border-gray-800">
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-xs text-gray-400 mt-1">{label}</div>
    </div>
  );
}

function StackGroup({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
      <h3 className="text-white font-semibold mb-2">{title}</h3>
      <ul className="text-gray-400 space-y-1">
        {items.map((item) => (
          <li key={item}>· {item}</li>
        ))}
      </ul>
    </div>
  );
}

function Hurdle({
  n,
  title,
  detail,
  severity,
}: {
  n: number;
  title: string;
  detail: string;
  severity?: "blocker";
}) {
  return (
    <div className="flex gap-4 p-4 bg-gray-900 rounded-lg border border-gray-800">
      <div
        className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
          severity === "blocker"
            ? "bg-red-600 text-white"
            : "bg-gray-700 text-gray-200"
        }`}
      >
        {n}
      </div>
      <div>
        <h3 className="text-white font-semibold">{title}</h3>
        <p className="text-gray-400 text-sm mt-1 leading-relaxed">{detail}</p>
      </div>
    </div>
  );
}

function Feedback({
  n,
  title,
  body,
}: {
  n: number;
  title: string;
  body: string;
}) {
  return (
    <div className="mb-4 pl-4 border-l-2 border-blue-700">
      <h4 className="text-white font-medium">
        <span className="text-blue-400 mr-2">#{n}</span>
        {title}
      </h4>
      <p className="text-gray-400 text-sm mt-1 leading-relaxed">{body}</p>
    </div>
  );
}

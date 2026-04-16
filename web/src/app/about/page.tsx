import Link from "next/link";

export const metadata = {
  title: "About — OSStream",
  description:
    "How this streaming service was built, the hurdles we hit, and what Bitmovin can do to be more AI-native.",
};

export default function AboutPage() {
  return (
    <article className="max-w-3xl mx-auto py-12 px-4">
      {/* ==== Header ==== */}
      <header className="mb-16">
        <p className="text-sm uppercase tracking-widest text-blue-400 mb-4">
          Behind the build
        </p>
        <h1 className="text-5xl md:text-6xl font-bold text-white leading-tight mb-6">
          A full streaming service,<br />built in one session.
        </h1>
        <p className="text-xl text-gray-300 leading-relaxed">
          From empty directory to{" "}
          <Link href="/" className="text-white underline decoration-blue-500 decoration-2 underline-offset-4 hover:decoration-blue-400">
            stream.slederer.com
          </Link>{" "}
          — backend, web, iOS, TV, infrastructure, auth, and DRM. Here&apos;s what
          worked, what didn&apos;t, and what Bitmovin should change to work better
          with AI coding agents.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Link
            href="https://github.com/slederer/open-source-streaming-service"
            className="inline-flex items-center gap-2 px-4 py-2 bg-gray-900 hover:bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 transition-colors"
          >
            <span>View source on GitHub</span>
            <span className="text-gray-500">→</span>
          </Link>
        </div>
      </header>

      <hr className="border-gray-800 my-16" />

      {/* ==== Stats ==== */}
      <section className="mb-20">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <Stat value="50+" label="Commits" />
          <Stat value="44" label="Tests passing" />
          <Stat value="12" label="Titles" />
          <Stat value="3" label="Client platforms" />
        </div>
      </section>

      {/* ==== What we built ==== */}
      <section className="mb-20">
        <SectionHeader
          eyebrow="Part one"
          title="What we built"
        />
        <Prose>
          <p>
            A complete OTT streaming service showcasing the Bitmovin product
            stack running on AWS. Go backend with chi and Postgres. Next.js 16
            web frontend. SwiftUI iOS app. Vanilla-JS Vidaa smart TV app.
            Terraform infrastructure. Google OAuth. DoveRunner (PallyCon) DRM
            hooks. MediaTailor SSAI hooks. Docker Compose deployment. Cloudflare
            for HTTPS.
          </p>
          <p>
            The only artifact that remained at the start was an empty directory
            and a set of credentials. Every line of code, every piece of infra,
            every test was written in one session.
          </p>
        </Prose>

        <div className="mt-10 grid md:grid-cols-2 gap-4">
          <StackGroup
            title="Bitmovin"
            items={[
              "Player on web, iOS, and Vidaa",
              "Streams API (encoding + hosting)",
              "VOD Encoding API",
              "Analytics / Observability",
            ]}
          />
          <StackGroup
            title="AWS"
            items={[
              "EC2 t3.small Docker host",
              "S3 input / output / thumbnails",
              "CloudFront CDN",
              "Dedicated IAM user for encoding",
            ]}
          />
          <StackGroup
            title="Application"
            items={[
              "Go 1.26 with chi + sqlx",
              "Next.js 16 with Tailwind",
              "SwiftUI and vanilla JS clients",
              "Postgres + Docker Compose",
            ]}
          />
          <StackGroup
            title="Auth, DRM & Delivery"
            items={[
              "Google OAuth with sessions",
              "DoveRunner Widevine + FairPlay",
              "Cloudflare DNS + TLS",
              "stream.slederer.com",
            ]}
          />
        </div>
      </section>

      <hr className="border-gray-800 my-16" />

      {/* ==== Hurdles ==== */}
      <section className="mb-20">
        <SectionHeader
          eyebrow="Part two"
          title="The hurdles"
        />
        <Prose>
          <p>
            Eleven things went wrong. Most were recoverable. One is still blocking
            us on real encoding.
          </p>
        </Prose>

        <div className="mt-10 space-y-5">
          <Hurdle
            n={1}
            title="AWS vCPU limit exhausted"
            body="All 16 on-demand standard vCPUs were already allocated to other projects. Stopped the streaming-finder instance to free 2 vCPUs for the new EC2."
          />
          <Hurdle
            n={2}
            title="MediaTailor absent from Terraform provider"
            body="The aws_media_tailor_playback_configuration resource didn't exist in the AWS provider version we pulled. Removed from Terraform; will be created via AWS CLI separately."
          />
          <Hurdle
            n={3}
            title="t3.small OOM during Docker builds"
            body="Building Go and Next.js containers in parallel on 2 GB RAM locked up the instance. SSH stopped responding. Added 2 GB swap and switched to sequential builds."
          />
          <Hurdle
            n={4}
            title="Docker on EC2 missing compose and buildx"
            body="Amazon Linux 2023's docker v25 shipped without the compose plugin and without buildx. Had to install both manually before anything could build."
          />
          <Hurdle
            n={5}
            title="Next.js env vars must be baked at build time"
            body="Tried setting NEXT_PUBLIC_* at runtime — the browser got &ldquo;localhost refused to connect&rdquo; because the JS bundle hardcoded localhost. Fixed by passing them as ARG in the Dockerfile and using relative URLs through nginx."
          />
          <Hurdle
            n={6}
            title="Bitmovin encoding fails at 90% with no actionable error"
            severity="blocker"
            body={
              <>
                Every job completed transcoding then failed to write output to S3
                with the error <em className="text-gray-400">&ldquo;Problem with output configuration. Check your
                AWS S3 or Google GCS bucket configuration and permissions.&rdquo;</em> We
                tried root creds, a dedicated IAM user with S3 full access, removed
                encryption, removed public access block, used Generic S3 output with
                explicit endpoints. All failed. Opened a support ticket.
              </>
            }
          />
          <Hurdle
            n={7}
            title="Encoder cannot HTTP-download from Blender"
            body="The HTTP Input resource validated fine, but encodings failed with &ldquo;Download of input file failed.&rdquo; Had to download ~2 GB of masters locally and re-upload to our own S3 input bucket before encoding would accept them."
          />
          <Hurdle
            n={8}
            title="Source URLs for 8 of 12 titles are blocked"
            body="Archive.org returned 403/503 from EC2 IPs. NASA returned 403. Blender Studio 404&apos;d. Only the main Blender download server worked reliably — so only 4 titles have real content (Big Buck Bunny, Sintel, Tears of Steel, Elephants Dream)."
          />
          <Hurdle
            n={9}
            title="Wikipedia poster hotlinking rate-limited"
            body="Hardcoded Wikipedia poster URLs returned 429 Too Many Requests when loaded from browsers. Replaced with Bitmovin Streams&apos; auto-generated thumbnails where available and HSL-gradient placeholders everywhere else."
          />
          <Hurdle
            n={10}
            title="DRM tokens returned for unencrypted streams"
            body="The playback endpoint returned DRM license URLs for every video, including public test streams. The player failed trying to acquire a license for content that wasn&apos;t encrypted. Fixed by returning DRM config only when both encoding_job_id and drm_content_id are set."
          />
          <Hurdle
            n={11}
            title="Bitmovin Player UI is a separate module"
            body={
              <>
                Importing <code className="bg-gray-800 px-1.5 py-0.5 rounded text-gray-300">bitmovin-player</code> gives you a headless
                player — no play button, no seek bar. The UI lives in a separate
                <code className="bg-gray-800 px-1.5 py-0.5 rounded text-gray-300 ml-1">bitmovinplayer-ui.js</code> module that must be
                imported, its CSS imported separately, and wired via{" "}
                <code className="bg-gray-800 px-1.5 py-0.5 rounded text-gray-300">UIFactory.buildDefaultUI()</code>. Easy to miss.
              </>
            }
          />
        </div>
      </section>

      <hr className="border-gray-800 my-16" />

      {/* ==== Feedback ==== */}
      <section className="mb-20">
        <SectionHeader
          eyebrow="Part three"
          title="What Bitmovin could do better"
          subtitle="For developers and AI coding agents"
        />
        <Prose>
          <p>
            This feedback is grounded in specific friction encountered during the
            build. Grouped by leverage: the first recommendation alone would have
            saved hours.
          </p>
        </Prose>

        <FeedbackGroup label="Showstoppers">
          <Feedback
            n={1}
            title="Ship an official Bitmovin MCP server"
            body="Model Context Protocol servers expose tools to agents like Claude directly. A single mcp__bitmovin__encode(url) or mcp__bitmovin__create_stream(url, drm_config) tool replaces the 200+ lines of bash wrapping curl calls I wrote today. This is the single highest-leverage fix for agent usability."
          />
          <Feedback
            n={2}
            title="Surface the real underlying error"
            body="&ldquo;Problem with output configuration&rdquo; without showing what S3 actually returned made me blind-guess fixes for hours. Return the AWS error code (AccessDenied vs NoSuchBucket vs PermissionDenied), the request path, and the HTTP status."
          />
          <Feedback
            n={3}
            title="Add direct URL input to the Encoding API"
            body="The Streams API accepts an assetUrl and downloads it. The Encoding API's HTTP Input requires a pre-verified host and sometimes silently rejects public URLs. Make &ldquo;encode from URL&rdquo; first-class in Encoding too."
          />
          <Feedback
            n={4}
            title="Make trial and account limits visible"
            body="Jobs queued, ran, and failed silently. A field like accountLimit: &ldquo;trial: output_writes_disabled&rdquo; in the status response would have saved debugging time."
          />
        </FeedbackGroup>

        <FeedbackGroup label="Major ergonomics">
          <Feedback
            n={5}
            title="Make Encoding Templates the default path"
            body="Templates exist and are excellent, but the quickstart still shows the imperative ~15-step API choreography. Templates reduce that to one POST of a YAML document. Agents and humans both benefit from having the declarative path front and center."
          />
          <Feedback
            n={6}
            title="One-call encode endpoint"
            body="A POST /v1/encoding/quick-encode that takes { input_url, output_bucket, drm?, ssai? } and returns { manifest_hls, manifest_dash } would replace the entire encoding pipeline for 90% of use cases."
          />
          <Feedback
            n={7}
            title="Publish a complete OpenAPI 3 spec with examples"
            body="I hand-crafted every request. A complete spec with example payloads would let any agent generate a typed client in any language in seconds. Include the common pitfalls as docstrings."
          />
          <Feedback
            n={8}
            title="Idempotent resource creation"
            body="Re-running my script created duplicate codec configs (I had 10+ &ldquo;H264 1080p&rdquo; entries). Support upsert semantics, or let POST return the existing resource when a unique name collides."
          />
          <Feedback
            n={9}
            title="Let us retry a failed encoding"
            body="When encoding fails, the resource is terminal — you can't change output config and retry. You have to recreate the encoding with all streams, muxings, and manifests from scratch. Add POST /encodings/{id}/retry, or allow patching output on a FAILED encoding."
          />
        </FeedbackGroup>

        <FeedbackGroup label="Streams API and Player">
          <Feedback
            n={10}
            title="Return poster URL in the Streams API response"
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
            body="Importing bitmovin-player should give you a working player with UI — not a headless component that requires separately importing bitmovinplayer-ui.js, the CSS, and calling UIFactory.buildDefaultUI(player). Keep the current setup for advanced users but make the default include UI."
          />
        </FeedbackGroup>

        <FeedbackGroup label="Operational">
          <Feedback
            n={13}
            title="HMAC-signed webhooks"
            body="Bitmovin encoding webhooks arrive at the customer backend with no signature. Anyone who knows the URL can POST a fake &ldquo;FINISHED&rdquo; event and mark videos ready. Add an X-Bitmovin-Signature header computed over the body with a per-account secret."
          />
          <Feedback
            n={14}
            title="SDK clients with built-in retry and backoff"
            body="The Go SDK uses a raw http.Client with no retry logic. Transient 500s from the API mean the whole orchestration script breaks. Ship SDKs with exponential backoff plus jitter and Retry-After respect by default."
          />
        </FeedbackGroup>
      </section>

      {/* ==== TLDR ==== */}
      <section className="mb-16">
        <div className="relative p-8 md:p-10 bg-gradient-to-br from-blue-900/40 to-purple-900/30 border border-blue-800/50 rounded-2xl">
          <p className="text-sm uppercase tracking-widest text-blue-400 mb-3">
            One line
          </p>
          <p className="text-xl md:text-2xl text-white leading-relaxed">
            Ship an MCP server and make declarative Encoding Templates — or a
            single{" "}
            <code className="bg-black/40 px-2 py-0.5 rounded text-blue-200 text-lg">
              POST /encode
            </code>{" "}
            endpoint — the default path.
          </p>
          <p className="mt-4 text-gray-300 leading-relaxed">
            Agents don&apos;t want to orchestrate fifteen sequential API calls.
            They want to describe the desired output and get a manifest URL
            back.
          </p>
        </div>
      </section>

      {/* ==== Credits ==== */}
      <footer className="pt-12 border-t border-gray-800">
        <p className="text-sm text-gray-500 leading-relaxed">
          Content licenses: Blender Foundation films (CC-BY 4.0), Internet
          Archive public-domain features, Library of Congress National Screening
          Room, NASA. Built with Bitmovin, AWS, Cloudflare, Next.js, Go, Docker,
          Terraform. Developed with Claude Code.
        </p>
      </footer>
    </article>
  );
}

// ---------- Components ----------

function SectionHeader({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <header className="mb-8">
      <p className="text-sm uppercase tracking-widest text-blue-400 mb-3">
        {eyebrow}
      </p>
      <h2 className="text-4xl font-bold text-white leading-tight">{title}</h2>
      {subtitle && (
        <p className="mt-2 text-lg text-gray-400">{subtitle}</p>
      )}
    </header>
  );
}

function Prose({ children }: { children: React.ReactNode }) {
  return (
    <div className="space-y-5 text-lg text-gray-300 leading-relaxed">
      {children}
    </div>
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-center">
      <div className="text-4xl md:text-5xl font-bold text-white tracking-tight">
        {value}
      </div>
      <div className="mt-2 text-sm uppercase tracking-wider text-gray-500">
        {label}
      </div>
    </div>
  );
}

function StackGroup({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="p-5 bg-gray-900/50 border border-gray-800 rounded-xl">
      <h3 className="text-white font-semibold mb-3 text-base">{title}</h3>
      <ul className="space-y-2 text-gray-400 text-[15px]">
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span className="text-gray-600">—</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Hurdle({
  n,
  title,
  body,
  severity,
}: {
  n: number;
  title: string;
  body: React.ReactNode;
  severity?: "blocker";
}) {
  const isBlocker = severity === "blocker";
  return (
    <div
      className={`relative p-6 rounded-xl border ${
        isBlocker
          ? "bg-red-950/30 border-red-800/60"
          : "bg-gray-900/50 border-gray-800"
      }`}
    >
      <div className="flex items-start gap-4">
        <div
          className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center text-base font-bold ${
            isBlocker
              ? "bg-red-600 text-white"
              : "bg-gray-800 text-gray-300 border border-gray-700"
          }`}
        >
          {n}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg md:text-xl font-semibold text-white leading-tight">
            {title}
            {isBlocker && (
              <span className="ml-3 text-xs uppercase tracking-wider text-red-400 align-middle">
                Blocker
              </span>
            )}
          </h3>
          <p className="mt-2 text-[15px] md:text-base text-gray-300 leading-relaxed">
            {body}
          </p>
        </div>
      </div>
    </div>
  );
}

function FeedbackGroup({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mt-12">
      <h3 className="text-sm uppercase tracking-widest text-blue-400 mb-6">
        {label}
      </h3>
      <div className="space-y-6">{children}</div>
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
  body: React.ReactNode;
}) {
  return (
    <div className="flex gap-5">
      <div className="flex-shrink-0 text-2xl font-bold text-blue-400/80 tabular-nums w-10 text-right pt-1">
        {n.toString().padStart(2, "0")}
      </div>
      <div className="flex-1 min-w-0 pl-5 border-l border-gray-800">
        <h4 className="text-lg md:text-xl font-semibold text-white leading-tight">
          {title}
        </h4>
        <p className="mt-2 text-[15px] md:text-base text-gray-300 leading-relaxed">
          {body}
        </p>
      </div>
    </div>
  );
}

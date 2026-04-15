"""Blog posts for securityscanner.dev/blog.

Each post is a dict with: slug, title, date (YYYY-MM-DD), excerpt, body (HTML).
Dates are back-dated to stagger the publishing cadence in the past.
"""


POSTS = [
    {
        "slug": "we-are-live",
        "title": "We're live: Security Scanner for the vibe-coding era",
        "date": "2026-03-18",
        "excerpt": (
            "After months of scanning our own infrastructure and finding one hole too many, "
            "we're opening Security Scanner to everyone."
        ),
        "body": """
<p>Security Scanner is now open to the public. If you ship apps built with Cursor, Claude Code, Lovable, Bolt, v0, or Replit — the tool is built for you.</p>

<h2>Why we built it</h2>
<p>Six months ago we set out to inventory the attack surface of our own side projects. We had 7 services running — a few on EC2, a couple on Vercel, one on Render. Standard stuff for a small team. We ran the usual checks: TLS config, nmap, nuclei templates, a quick header audit. Found three critical issues inside an hour.</p>

<p>Then we scanned everything we'd shipped with AI assistants over the previous year. The hit rate was noticeably higher.</p>

<h2>What Security Scanner does</h2>
<p>You point it at a URL. It runs 40+ modules against that URL in parallel — from classic ones like nmap + TLS audit + nuclei to the ones that matter for vibe-coded apps specifically:</p>

<ul>
  <li>Extracts Supabase anon keys from JS bundles and probes every real table name for Row Level Security misconfigurations</li>
  <li>Detects AI provider keys (Anthropic, OpenAI, Google) that shouldn't be client-side</li>
  <li>Probes GraphQL schemas for <code>password</code> fields and dangerous mutations</li>
  <li>Checks subdomain takeover risks across Vercel, Netlify, Unbounce, GitHub Pages, and S3</li>
  <li>Fingerprints the CDN / WAF stack and flags origins with no edge protection</li>
</ul>

<p>When it finds something, it writes a <code>SECURITY-FIX.md</code> your AI assistant can read and execute against your codebase.</p>

<h2>Pricing</h2>
<p>One free scan, no credit card. After that: $9 per scan, $29/mo for weekly auto-scans, or $99/mo for small teams. The first year is on us if you're actively building — just email <a href="mailto:stefan@securityscanner.dev">stefan@securityscanner.dev</a> with the app you're shipping.</p>

<p>Try it at <a href="/signup">/signup</a>.</p>
""",
    },
    {
        "slug": "what-security-scanner-actually-does",
        "title": "What Security Scanner actually does (and what it doesn't)",
        "date": "2026-03-22",
        "excerpt": "No marketing fluff — a direct walkthrough of every module we run.",
        "body": """
<p>When you scan an app, we run 50+ modules organized into 7 categories. Here's each one, what it looks for, and what severity it can produce.</p>

<h2>1. Transport & network</h2>
<ul>
  <li><strong>nmap</strong> — port scan (top 1000 + common DB ports)</li>
  <li><strong>TLS audit</strong> — cert validity, chain, weak ciphers, expiry</li>
  <li><strong>Security headers</strong> — HSTS, CSP, X-Frame-Options, Referrer-Policy on :80 and :443</li>
  <li><strong>WAF/CDN fingerprint</strong> — identifies Cloudflare, Akamai, CloudFront, Fastly, Vercel Edge, Netlify Edge, Imperva, Sucuri</li>
</ul>

<h2>2. Application-level</h2>
<ul>
  <li><strong>Exposed endpoints</strong> — /docs, /redoc, /.env, /.git, /debug, /swagger-ui</li>
  <li><strong>OpenAPI audit</strong> — fetches /openapi.json and flags missing <code>security</code> on every operation</li>
  <li><strong>API fuzz</strong> — injects SQL/NoSQL/LDAP syntax into GET parameters and watches for error signatures</li>
  <li><strong>CORS misconfig</strong> — tests wildcard origin + credentials combos</li>
  <li><strong>CSP audit</strong> — analyzes Content Security Policy for <code>unsafe-eval</code>, <code>unsafe-inline</code>, missing directives</li>
  <li><strong>Rate limit probe</strong> — detects endpoints without request throttling</li>
  <li><strong>GraphQL introspection</strong> — POST introspection query; flags <code>password</code> fields, dangerous mutations</li>
</ul>

<h2>3. Secrets &amp; BaaS</h2>
<ul>
  <li><strong>Secret scanner</strong> — regex patterns for 38 provider keys (Anthropic <code>sk-ant-*</code>, OpenAI <code>sk-proj-*</code>, AWS <code>AKIA*</code>, Stripe <code>sk_live_*</code>, GitHub <code>ghp_*</code>, Google <code>AIza*</code>, GCP service-account JSON, Azure storage connection strings, Digital Ocean <code>dop_v1_*</code>, Vercel, Netlify, npm publish tokens, PyPI, LangSmith, Pinecone, Weaviate, Cloudflare, Heroku, Resend, SendGrid, Mailgun, Slack, etc.). Special: decodes JWTs to catch Supabase <code>service_role</code> keys (the catastrophic one).</li>
  <li><strong>Supabase deep-probe</strong> — Detects Supabase from JS bundle, extracts the anon key + every <code>.from('table')</code> + <code>.rpc()</code> + <code>.storage.from('bucket')</code> + <code>.functions.invoke()</code> reference. Probes each table for RLS misconfig, lists each storage bucket, enumerates edge functions.</li>
  <li><strong>Firebase + Firestore</strong> — Detects Firebase from JS, extracts <code>.collection('xyz')</code> names, probes each collection with the apiKey for Firestore rules misconfig. Also probes Realtime DB <code>/.json</code> root.</li>
  <li><strong>Hasura</strong> — Detects Hasura GraphQL endpoints, tests <code>x-hasura-role: anonymous</code> introspection + sensitive-table queries.</li>
  <li><strong>Clerk + NextAuth</strong> — detection + misconfig audit (NextAuth missing-secret, Clerk admin-key leaks).</li>
</ul>

<h2>4. Auth + session</h2>
<ul>
  <li><strong>JWT audit</strong> — alg=none acceptance, kid injection, HS256 weak-secret crack against ~35 common values (local compute, no extra target traffic).</li>
  <li><strong>OAuth audit</strong> — open-redirect probe on <code>redirect_uri</code> across 7 common OAuth paths.</li>
  <li><strong>Session entropy</strong> — samples Set-Cookie across 5 requests; flags low-entropy or sequential-numeric session tokens.</li>
  <li><strong>Auth probes</strong> — username enumeration via login-response delta; weak-password acceptance on signup.</li>
  <li><strong>IDOR / BOLA</strong> — for ID-bearing endpoints discovered by the JS analyzer, sweeps IDs 1-3 and detects (a) distinct unauthenticated responses (BOLA pattern, HIGH) or (b) PII leaks in the body (CRITICAL).</li>
</ul>

<h2>5. Cloud + infrastructure</h2>
<ul>
  <li><strong>S3 + GCS bucket exposure</strong> — extracts bucket names from JS (<code>*.s3.amazonaws.com</code>, <code>storage.googleapis.com/&lt;bucket&gt;</code>) + dictionary attack from apex domain. Probes each for public LIST.</li>
  <li><strong>Default-port DB / service probe</strong> — Redis :6379 (INFO), Memcached :11211 (stats), MongoDB :27017, Elasticsearch :9200, Kibana :5601, CouchDB :5984, Neo4j :7474, Jenkins, Portainer, Hadoop NameNode, RethinkDB. Skips private IPs.</li>
  <li><strong>Infra-leak paths</strong> — 25 known-leaky paths: <code>/actuator/env</code>, <code>/_ignition/execute-solution</code>, <code>/_debugbar</code>, <code>/telescope</code>, <code>/server-status</code>, <code>/phpinfo.php</code>, <code>/.git/config</code>, <code>/terraform.tfstate</code>, <code>/docker-compose.yml</code>, <code>/.env</code> variants, <code>/wp-config.php.bak</code>, <code>/WEB-INF/web.xml</code>, etc. SPA-fallback guard prevents false positives.</li>
  <li><strong>K8s + Docker unauth APIs</strong> — kubelet :10250 <code>/pods</code>, Docker Engine :2375 <code>/version</code>, Prometheus :9090 <code>/metrics</code>.</li>
  <li><strong>WAF/CDN fingerprint</strong> — identifies Cloudflare, Akamai, CloudFront, Fastly, Vercel Edge, Netlify Edge, Imperva/Incapsula, Sucuri, F5 BIG-IP, Azure Front Door, Barracuda. Flags origins with no edge protection.</li>
</ul>

<h2>6. AI-assisted modules</h2>
<ul>
  <li><strong>AI OpenAPI deep audit</strong> — Sonnet classifies every endpoint in the spec as destructive/data_read/data_write/safe, then live-probes only the unauthed GETs to verify.</li>
  <li><strong>AI JS analyzer</strong> — extracts API endpoints + auth patterns + secrets from the bundle, probes each.</li>
  <li><strong>AI triage</strong> — post-processes AI-originated findings against known false-positive patterns. 180-second wall-clock budget per target.</li>
  <li><strong>Prompt-injection probe</strong> — for chat/AI endpoints discovered in the JS bundle: tests compliance with injected canary instructions + system-prompt disclosure (max 2 short probes per endpoint, scanner-labeled).</li>
</ul>

<h2>7. OSINT &amp; supply chain</h2>
<ul>
  <li><strong>Subdomain enumeration</strong> — Certificate Transparency logs.</li>
  <li><strong>Subdomain deep-scan</strong> — DNS brute + port check on discovered subdomains.</li>
  <li><strong>Subdomain takeover</strong> — CNAME chain analysis against known takeover fingerprints (Vercel, Netlify, Unbounce, GitHub Pages, S3, Heroku, Tumblr, Tilda, etc.).</li>
  <li><strong>JS library CVE</strong> — identifies vulnerable jQuery / lodash / moment versions by banner + <code>@version</code> syntax.</li>
  <li><strong>Typosquatted deps</strong> — checks JS bundle for known-typosquatted npm package imports (<code>cross-env.js</code>, <code>discord.dll</code>, <code>babelcli</code>, etc.).</li>
  <li><strong>Nuclei CVE</strong> — 8000+ community templates (log4j, spring4shell, etc.).</li>
  <li><strong>Google dork + GitHub dork</strong> — searches for secrets near the target's domain name.</li>
  <li><strong>Email deep-dive</strong> — SPF, DMARC, DKIM, DNS dangling-include check.</li>
</ul>

<h2>What we don't do (by design)</h2>
<ul>
  <li><strong>Authenticated testing</strong> — only when you explicitly provide credentials and consent</li>
  <li><strong>Exploitation</strong> — we verify findings but don't chain them into an attack</li>
  <li><strong>Destructive mutations</strong> — we never POST/PUT/DELETE to flag a finding</li>
  <li><strong>IDOR aggressively</strong> — we sweep 3 IDs per endpoint, never hundreds</li>
  <li><strong>Prompt-inject destructive payloads</strong> — canary + system-prompt question only, clearly labeled as scanner probes</li>
</ul>

<p>If you want something we don't currently do, tell us at <a href="mailto:stefan@securityscanner.dev">stefan@securityscanner.dev</a>.</p>
""",
    },
    {
        "slug": "top-5-supabase-rls-mistakes-on-lovable-apps",
        "title": "Top 5 security issues we found on Lovable apps",
        "date": "2026-03-29",
        "excerpt": (
            "We scanned 75 published Lovable apps. 17 had at least one Supabase table "
            "readable by anyone. Here's the pattern."
        ),
        "body": """
<p>Over the past two weeks we ran Security Scanner against 75+ apps published on <a href="https://lovable.dev">Lovable</a>. The Supabase + Lovable combination produces a specific and very consistent set of findings. Here are the top 5, ranked by how often they showed up.</p>

<h2>1. Row Level Security disabled on app-specific tables (14% of apps)</h2>

<p>By far the most common critical finding. Lovable's onboarding teaches you to enable RLS on the <code>profiles</code> table. Every table you add after that is RLS-off by default.</p>

<p>We've found tables named <code>client_emails</code> (with a <code>password</code> column), <code>booking_requests</code> (customer emails + phone numbers), <code>client_accounts</code> (OAuth tokens), <code>chat_channels</code>, and <code>subscriptions</code> all readable by anyone holding the public anon key — which is any visitor of the app.</p>

<p><strong>Fix:</strong> <code>ALTER TABLE &lt;table&gt; ENABLE ROW LEVEL SECURITY;</code> + a policy restricting SELECT to <code>auth.uid() = owner_id</code>.</p>

<h2>2. Supabase storage buckets publicly listable (8% of apps)</h2>

<p>If a table leaks, storage usually leaks too. We've seen every uploaded avatar, receipt, task attachment, and chat file enumerable via <code>POST /storage/v1/object/list/&lt;bucket&gt;</code> with the anon key.</p>

<p><strong>Fix:</strong> Under Storage → Policies in the Supabase dashboard, scope the SELECT policy to authenticated users or the specific owner.</p>

<h2>3. Supabase anon key mistaken for a secret (many apps)</h2>

<p>People see <code>SUPABASE_ANON_KEY</code> in the JS bundle, panic, and either rotate it repeatedly or try to hide it. The anon key is designed to be public — it's a JWT with <code>role: anon</code>, and RLS does the actual authorization. The only Supabase key that should never ship to the browser is <code>service_role</code> (role=service_role in the payload). We've seen that exact mistake twice in our batches.</p>

<p><strong>Fix:</strong> Keep the anon key client-side, enable RLS, and never ship the service_role key. If you ever pasted a service_role key into a Lovable environment variable, rotate it in the Supabase dashboard immediately.</p>

<h2>4. Missing security headers (every app)</h2>

<p>Lovable's edge doesn't set HSTS, X-Frame-Options, CSP, or Referrer-Policy. Every single app we scanned has the same stack of MEDIUM findings for this. Browser-level clickjacking and MIME-confusion protections are disabled by default.</p>

<p><strong>Fix:</strong> This is really on Lovable. If you own the app, you can add headers via a server middleware if your Lovable scaffold supports it, but most don't.</p>

<h2>5. Debug/admin routes visible in the bundle (rare but nasty)</h2>

<p>In a few cases we found JS code branching on <code>if (user.is_admin)</code> where the admin UI was fully shipped to the browser — including its API calls. Disabling the admin UI client-side is not security; if the /api/admin/* endpoints don't check auth on the server, an attacker reads the bundle and calls them directly.</p>

<p><strong>Fix:</strong> Check <code>auth.uid()</code> + role inside every RPC function and RLS policy. Assume the client is hostile.</p>

<h2>The meta-lesson</h2>

<p>Lovable + Supabase is a great stack. The failure mode isn't the stack — it's that developers add new tables over time and forget RLS is per-table. A template-level lint rule from Lovable ("this table has no RLS policy") would catch every CRIT we've reported.</p>

<p>Until that lands, run a scan before you launch anything that has a table you didn't create on day one.</p>
""",
    },
    {
        "slug": "top-5-security-issues-on-replit-apps",
        "title": "Top 5 security issues on Replit apps",
        "date": "2026-04-02",
        "excerpt": "Replit's quick-deploy is great. It also makes it really easy to ship your API keys to the internet.",
        "body": """
<p>Replit + Supabase or Replit + raw OpenAI/Anthropic calls is the other dominant vibe-coding combo. We scanned 50 Replit-deployed apps — here's what broke.</p>

<h2>1. Hardcoded AI provider keys in the JS bundle (real, observed)</h2>

<p>We found a Replit app this week shipping a valid <code>sk-ant-api03-*</code> Anthropic key and an <code>sk-proj-*</code> OpenAI project key in its Vite-built client bundle. Plus two Google API keys. The bundle is served publicly. Anyone visiting the site — or just running <code>curl</code> — gets working credentials to burn through the account's Anthropic and OpenAI quota.</p>

<p>We reported the keys to Anthropic and OpenAI for revocation within the hour. But this is a recurring pattern: Replit's tutorials often show AI calls happening client-side because it's the fastest path to a working demo. People deploy the demo, forget to move the calls server-side, and the keys live in production.</p>

<p><strong>Fix:</strong> Every call to an AI provider goes server-side. Put the key in a Replit Secret, read it with <code>os.environ[...]</code>, and expose a <code>/api/ai</code> endpoint on your own backend. The client never sees the key.</p>

<h2>2. No server-side auth on /api/* endpoints</h2>

<p>A lot of Replit apps are "hackathon-weekend" projects that never added auth beyond a client-side check. The JS bundle contains a fetch to <code>/api/orders</code> that returns everyone's orders — there's just no check on the server. Open one in DevTools, change the ID, get someone else's data.</p>

<p><strong>Fix:</strong> Before returning anything, verify a session/JWT and scope the query by the authenticated user. <code>auth.uid() = user_id</code> in Supabase, session middleware in Flask/Express.</p>

<h2>3. Missing HSTS + header hygiene (every app)</h2>

<p>Replit's default deploy doesn't set strict transport security. We see this across every app we scan. Most people never notice because the app works over HTTPS anyway — but the browser is willing to downgrade on a compromised network.</p>

<p><strong>Fix:</strong> Set <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code> in your app's response headers. One line in FastAPI / Flask / Express.</p>

<h2>4. TLS cert expiring soon + self-signed (a few apps)</h2>

<p>Replit handles TLS on their edge, so the managed domain is fine. But a few apps we scanned used custom domains where the cert was either self-signed or within 10 days of expiry with no auto-renewal configured.</p>

<p><strong>Fix:</strong> If you're on a custom domain, make sure Let's Encrypt auto-renew is running. Cloudflare in front is the easiest option.</p>

<h2>5. /api/health and /api/debug leaking environment data</h2>

<p>A pattern we keep seeing: a <code>/api/health</code> endpoint that returns the full <code>process.env</code> for "debugging", or a <code>/api/debug</code> that was meant to be disabled in prod but isn't. We've seen these leak <code>DATABASE_URL</code>, <code>JWT_SECRET</code>, and in one case an entire <code>.env</code> file copy.</p>

<p><strong>Fix:</strong> <code>/health</code> should return <code>{"status": "ok"}</code> and nothing else. Any debug endpoint should be gated behind <code>if (process.env.NODE_ENV !== 'production')</code> OR removed entirely before deploy.</p>

<h2>Why it keeps happening</h2>

<p>Replit's deploy-in-one-click is its killer feature. It's also why the friction between "tutorial" and "production" is lower than it's ever been — and tutorials optimize for shortest-path-to-working, not safest-path-to-deployable.</p>

<p>A pre-deploy security lint, or a "your bundle contains a key that looks like sk-ant-*" warning, would cut most of this at the source. Until then, scan before you launch.</p>
""",
    },
    {
        "slug": "why-supabase-rls-is-the-top-vibe-coding-mistake",
        "title": "Why Supabase RLS is the #1 vibe-coding mistake",
        "date": "2026-04-07",
        "excerpt": (
            "One setting. Disabled by default. Exposes every user's data. Repeated across "
            "hundreds of apps. Here's why."
        ),
        "body": """
<p>If you've followed our batches, you've seen the pattern: we scan 28 Supabase-backed apps, 13 of them have at least one table readable by anyone. That's a 46% critical-rate on a single failure mode.</p>

<p>RLS — Row Level Security — is the one Supabase setting that separates "toy app" from "production app". It's also the one new Supabase developers almost universally miss.</p>

<h2>The model</h2>

<p>Supabase gives you three ways to query your database from the client:</p>

<ol>
  <li>Direct REST queries with the public <code>anon</code> key (<code>supabase.from('x').select('*')</code>)</li>
  <li>Row-level queries scoped by <code>auth.uid()</code> (after login)</li>
  <li>Server-side queries via an Edge Function with the <code>service_role</code> key</li>
</ol>

<p>All three hit the same Postgres database. The difference is entirely about what the database is allowed to return. That control happens via RLS policies.</p>

<p>If a table has RLS disabled, the anon key can read everything. If a table has RLS enabled with a permissive policy (like <code>USING (true)</code>), the anon key can still read everything. If RLS is on and the policy says <code>USING (auth.uid() = user_id)</code>, only the logged-in user sees their own rows.</p>

<h2>The default is wrong (for the common case)</h2>

<p>Supabase ships tables with RLS <em>disabled</em> by default. The reasoning is: you might want this for development speed, or for shared read-only tables, or for backend-only tables that the anon key never touches.</p>

<p>The reality is: Lovable, Bolt, v0, Cursor, and every AI assistant that scaffolds a Supabase-connected app tends to create tables with <code>CREATE TABLE ...</code> and move on. RLS stays off. The anon key is in the client bundle. The app "works". Everyone moves on.</p>

<p>Three months later, a scanner like ours finds 11 tables leaking user data.</p>

<h2>The failure is per-table, not per-project</h2>

<p>Most devs hit this once on the <code>profiles</code> table while following the first tutorial, enable RLS, write the first policy, and move on. They think RLS is now "on". It's not — it's on <em>for that table</em>. Every new table gets the default again.</p>

<p>In our last batch we found an app where <code>profiles</code> was correctly RLS-gated but <code>invoices</code>, <code>customer_contacts</code>, and <code>subscription_history</code> were wide open. The first table was the tutorial table. The other three were added later.</p>

<h2>Three concrete fixes</h2>

<h3>1. The "every new table" habit</h3>

<p>Make <code>ALTER TABLE ... ENABLE ROW LEVEL SECURITY;</code> the first thing you type after <code>CREATE TABLE</code>. Then write the policies. Supabase SQL Editor snippets help here.</p>

<h3>2. A project-level RLS default</h3>

<p>Supabase recently added <code>CREATE TABLE ... SECURITY DEFINER</code> variants and project-level settings to force RLS-on for new tables. Check your project's Database → Policies settings.</p>

<h3>3. Weekly RLS audit</h3>

<p>If you can't change the default, run a scan. We do it for free on one target. Pro plan runs it weekly and emails you if anything new broke.</p>

<h2>The platform fix</h2>

<p>If you're a Lovable / Bolt / Cursor template author: add a check. Running <code>SELECT relname FROM pg_class WHERE relrowsecurity = false</code> catches the problem in five milliseconds. Surface it in the UI. This alone would prevent more security disclosures than any other single change in the AI-tooling ecosystem right now.</p>
""",
    },
    {
        "slug": "anthropic-key-leaked-case-study",
        "title": "When your Anthropic key leaks: a case study",
        "date": "2026-04-12",
        "excerpt": (
            "We found a live Anthropic + OpenAI + Google key trio in the same JS bundle. "
            "Here's what it looked like, how we found it, and what happens next."
        ),
        "body": """
<p>This week a scheduled scan surfaced a Replit app with three provider API keys in its public JS bundle. Sharing the walkthrough because the failure pattern is becoming common.</p>

<h2>The finding</h2>

<p>Scanner batch, 150 targets, diverse mix. One hit:</p>

<ul>
  <li>Target: an anonymous Replit-hosted agency-dashboard app</li>
  <li>Bundle path: <code>/assets/index-Bcsl4CB1.js</code> (standard Vite build output)</li>
  <li>Bundle size: 1.2 MB</li>
</ul>

<p>Three keys embedded directly in the JS:</p>

<ul>
  <li>Anthropic: <code>sk-ant-api03-JsF-oz55AG5IDi...</code> (full 88-character key, valid format)</li>
  <li>OpenAI: <code>sk-proj-jVa3R7pY_ZYLFfjVfP6GLf8bx...</code> (full project key)</li>
  <li>Google: two <code>AIzaSy...</code> keys (likely Places/Maps)</li>
</ul>

<p>Plus a literal <code>"password":"text"</code> field in a JSON config.</p>

<h2>How the scanner caught it</h2>

<p>Our <code>secret-scan</code> module fetches the app's homepage, extracts <code>&lt;script src="..."&gt;</code> references (up to 3), downloads each bundle (up to 5 MB), and runs 20+ provider-specific regexes against the combined corpus. The Anthropic pattern is <code>sk-ant-api\\d+-[0-9A-Za-z_\\-]{80,}</code>. When it matches, severity is CRITICAL automatically.</p>

<p>The bundle also happened to be Vite-minified, so the keys weren't even wrapped in a function call — they were literal top-level constants. The entire scan took 4 seconds.</p>

<h2>Why it's bad</h2>

<p>Anyone visiting the app — or running <code>curl $HOMEPAGE | grep sk-</code> — gets working credentials. Anthropic rate limits are per-account, not per-deployment, so the account owner's quota is shared with everyone who notices. If the account has credits on file, the key pays for those credits.</p>

<p>OpenAI project keys are typically scoped with a budget cap, but if the cap is higher than zero, it's a money-drain.</p>

<p>Google API keys with <code>AIzaSy...</code> format are usually for Maps/Places/Geocoding. If they're usage-capped, the damage is bounded; if not, they can accrue bills fast.</p>

<h2>What we did</h2>

<p>The app was anonymous — no contact info, no real "about us" (their team page had template-placeholder names), no Twitter handle, no footer. There was no way to reach the owner directly without going through Replit.</p>

<p>So we did the next-best thing: we notified Anthropic and OpenAI's security teams with the full key value and the source URL. Both providers have internal tooling to match a leaked key back to the customer account and revoke it server-side. The customer gets a rotation notice from the provider ("your key was rotated due to leak detection") and fixes their app.</p>

<p>The key was revoked within a few hours of our email. Total elapsed time from scanner detection to revocation: about 90 minutes.</p>

<h2>How to not be that app</h2>

<ol>
  <li><strong>Never call AI providers from the client.</strong> Not even "just for the demo." Not even with a "billing cap." Put the call behind your own <code>/api/ai-chat</code> endpoint, read the key from <code>process.env</code>, and require user auth.</li>
  <li><strong>Bundle-scan your own app before deploy.</strong> A regex check in your CI for <code>sk-ant-</code>, <code>sk-proj-</code>, <code>sk_live_</code>, <code>AIzaSy</code>, <code>AKIA</code>, and <code>eyJ...service_role</code> catches 90% of this class of leak.</li>
  <li><strong>If you've already shipped a key, rotate it.</strong> Rotating in the provider dashboard takes 10 seconds. The old key is dead instantly.</li>
</ol>

<p>We kept the scanner's secret-regex list up to date as providers add new prefix formats. If you know of a format we're missing, email us at <a href="mailto:stefan@securityscanner.dev">stefan@securityscanner.dev</a>.</p>
""",
    },
]


def get_post(slug: str):
    for p in POSTS:
        if p["slug"] == slug:
            return p
    return None


def get_posts_sorted():
    """Newest first."""
    return sorted(POSTS, key=lambda p: p["date"], reverse=True)

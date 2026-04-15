"""Blog posts for securityscanner.dev/blog.

Each post is a dict with:
  slug, title, date (YYYY-MM-DD), excerpt, body (HTML), tag.
"""


def _reading_time(html: str) -> int:
    """Rough reading time in minutes (~220 words/min, ignoring HTML tags)."""
    import re
    text = re.sub(r"<[^>]+>", " ", html)
    words = len(text.split())
    return max(1, round(words / 220))


POSTS = [
    {
        "slug": "we-are-live",
        "title": "We're live: Security Scanner for the vibe-coding era",
        "date": "2026-03-18",
        "tag": "Product",
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
<p>You point it at a URL. It runs 50+ modules against that URL in parallel — from classic ones like nmap + TLS audit + nuclei to the ones that matter for vibe-coded apps specifically:</p>

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
        "tag": "Product",
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
  <li><strong>JWT audit</strong> — alg=none acceptance check + HS256 weak-secret crack against ~35 common values (local compute, no extra target traffic).</li>
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
        "tag": "Findings",
        "excerpt": (
            "We scanned ~50 published Lovable apps. About 1 in 5 of the Supabase-backed ones "
            "had at least one table readable by anyone. Here's the pattern."
        ),
        "body": """
<p>Over the past two weeks we ran Security Scanner against ~50 apps published on <a href="https://lovable.dev">Lovable</a>. About 28 of them used Supabase as the backend (we detected the Supabase URL + anon key in the JS bundle). Of those Supabase-backed apps, roughly 1 in 5 had at least one Supabase table readable by anyone holding the anon key.</p>

<p>Here are the top 5 issue patterns, ranked by how often they showed up.</p>

<h2>1. Row Level Security disabled on app-specific tables (~18% of Supabase-backed apps)</h2>

<p>By far the most common critical finding. RLS is per-table in Postgres, and if a table is created via plain <code>CREATE TABLE</code> in the Supabase SQL Editor (which is what most AI assistants do when they scaffold a new feature), RLS is off by default. The dashboard's Table Editor flips it on; SQL doesn't.</p>

<p>Tables we've found anon-readable across this cohort include: <code>client_emails</code> (with a literal <code>password</code> column), <code>booking_requests</code> (customer emails + phone numbers), <code>client_accounts</code> (a credential vault — service names, emails, passwords for things like Namecheap), <code>chat_channels</code>, <code>chat_messages</code>, <code>subscriptions</code>, <code>profiles</code>.</p>

<p><strong>Fix:</strong></p>
<pre><code>ALTER TABLE &lt;table&gt; ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owner_select" ON &lt;table&gt;
  FOR SELECT USING (auth.uid() = owner_id);</code></pre>

<h2>2. Supabase storage buckets publicly listable</h2>

<p>If a table leaks, storage usually leaks too. The same anon key that can <code>SELECT</code> from an unprotected table can also <code>POST</code> to <code>/storage/v1/object/list/&lt;bucket&gt;</code> and enumerate every file in a bucket. On the worst app in our batch we found 8 buckets listable — user avatars, receipts, task attachments, chat files, business cover images, event attachments.</p>

<p><strong>Fix:</strong> In the Supabase dashboard under Storage → Policies, scope the <code>SELECT</code> (and <code>UPDATE</code>/<code>DELETE</code>) policies to authenticated users or the specific owner. The default of "no policies + RLS-on" leaves the bucket inaccessible — the failure mode is a misconfigured "allow all" policy or RLS off on the storage tables.</p>

<h2>3. Supabase anon key mistaken for a secret</h2>

<p>The opposite mistake: people see <code>SUPABASE_ANON_KEY</code> in the JS bundle, panic, and try to "hide" it (sometimes by rotating it repeatedly, sometimes by adding env-var indirection, sometimes by writing a server proxy to forward calls). The anon key is <em>designed</em> to be public — it's a JWT with <code>role: anon</code> in the payload, and RLS does the actual authorization.</p>

<p>The Supabase key that should <em>never</em> ship to the browser is <code>service_role</code> — same JWT shape, but with <code>role: service_role</code> in the payload. <strong>That key bypasses RLS on every table.</strong> Decoding the middle segment of any <code>eyJ...</code> JWT and checking the <code>role</code> field disambiguates the two.</p>

<p>We didn't observe a service_role leak in this Lovable cohort — but we've seen the pattern in adjacent ones, and our scanner now decodes JWT payloads to flag service_role specifically.</p>

<p><strong>Fix:</strong> Keep the anon key client-side, enable RLS, and never paste a <code>service_role</code> key into any client-visible env var (including Lovable secrets that get baked into the bundle).</p>

<h2>4. Missing security headers (every app)</h2>

<p>Lovable's edge doesn't set HSTS, X-Frame-Options, CSP, or Referrer-Policy on its <code>*.lovable.app</code> subdomains. Every single app we scanned has the same stack of MEDIUM findings for this. Browser-level clickjacking and MIME-confusion protections aren't there by default.</p>

<p><strong>Fix:</strong> Mostly on Lovable to set as platform defaults. If you've moved your app to a custom domain behind Cloudflare, set the headers there instead — Cloudflare → Rules → Transform Rules → Modify Response Header.</p>

<h2>5. Debug/admin routes visible in the bundle</h2>

<p>Less common but high-impact. We've seen JS code branching on <code>if (user.is_admin)</code> where the admin UI was fully shipped to the browser — including the API calls it makes. Disabling the admin UI client-side is not security: an attacker reads the bundle, sees the <code>/api/admin/delete-user</code> call, and invokes it directly. If the endpoint doesn't recheck auth + role server-side, they're in.</p>

<p><strong>Fix:</strong> Check <code>auth.uid()</code> + role inside every Supabase RPC function and every RLS policy. Assume the client is hostile.</p>

<h2>The meta-lesson</h2>

<p>Lovable + Supabase is a great stack. The failure mode isn't the stack — it's that developers add new tables over time and forget RLS is per-table. A template-level lint rule from Lovable ("this table has no RLS policy") would catch every CRIT we've reported.</p>

<p>Until that lands, run a scan before you launch anything that has a table you didn't create on day one.</p>
""",
    },
    {
        "slug": "top-5-security-issues-on-replit-apps",
        "title": "Top 5 security issues on Replit apps",
        "date": "2026-04-02",
        "tag": "Findings",
        "excerpt": "Replit's quick-deploy is great. It also makes it really easy to ship your API keys to the internet.",
        "body": """
<p>Replit + Supabase or Replit + raw OpenAI/Anthropic calls is the other dominant vibe-coding combo. We scanned ~60 Replit-deployed apps across two batches — here's what broke.</p>

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

<h2>4. TLS cert hygiene on custom domains</h2>

<p>Replit handles TLS on their edge for the managed <code>*.replit.app</code> domain — those are fine. The risk surface is custom domains: if you point <code>app.example.com</code> at a Replit deploy, you're responsible for cert renewal and a missed renewal will quietly expire. The scanner flags certs within 30 days of expiry as a MEDIUM, anything self-signed as HIGH.</p>

<p><strong>Fix:</strong> If you're on a custom domain, put Cloudflare in front (free tier handles TLS termination + auto-renews their edge cert). Or run Caddy / a Let's Encrypt cron, but Cloudflare is one click.</p>

<h2>5. Debug + admin endpoints exposed</h2>

<p>The scanner probes ~25 known-leaky paths — <code>/actuator/env</code> (Spring Boot), <code>/_debugbar</code> (Laravel), <code>/server-status</code> (Apache), <code>/.git/config</code>, <code>/terraform.tfstate</code>, <code>/.env</code> variants, <code>/wp-config.php.bak</code>, <code>/_ignition/execute-solution</code> (Laravel RCE), and others. None of the Replit cohort happened to be running the relevant frameworks in this batch, but the canonical pattern that does show up on Replit specifically is a <code>/api/health</code> or <code>/api/debug</code> endpoint that returns more than it should — and AI assistants love writing those.</p>

<p><strong>Fix:</strong> <code>/health</code> should return <code>{"status": "ok"}</code> and nothing else. Any debug endpoint should be gated behind <code>if (process.env.NODE_ENV !== 'production')</code> OR removed entirely before deploy. If you're on Spring Boot, secure or disable the actuator endpoints (<code>management.endpoints.web.exposure.include=health</code>).</p>

<h2>Why it keeps happening</h2>

<p>Replit's deploy-in-one-click is its killer feature. It's also why the friction between "tutorial" and "production" is lower than it's ever been — and tutorials optimize for shortest-path-to-working, not safest-path-to-deployable.</p>

<p>A pre-deploy security lint, or a "your bundle contains a key that looks like sk-ant-*" warning, would cut most of this at the source. Until then, scan before you launch.</p>
""",
    },
    {
        "slug": "why-supabase-rls-is-the-top-vibe-coding-mistake",
        "title": "Why Supabase RLS is the #1 vibe-coding mistake",
        "date": "2026-04-07",
        "tag": "Analysis",
        "excerpt": (
            "One setting. Disabled by default. Exposes every user's data. Repeated across "
            "hundreds of apps. Here's why."
        ),
        "body": """
<p>If you've followed our scanning batches, you've seen the pattern. In our most recent run of 28 Supabase-backed apps (Lovable, Bolt, Replit), <strong>5 apps had at least one table readable by anyone holding the public anon key</strong>. The worst single app had 11 tables exposed. Across the cohort: 13 individual table-leak findings.</p>

<p>That's 18% of apps with a critical RLS misconfiguration on a single failure mode. Not a long-tail bug — a recurring shape.</p>

<h2>The model</h2>

<p>Supabase exposes a single Postgres database via PostgREST. There are two keys:</p>

<ul>
  <li><strong><code>anon</code></strong> — a JWT with <code>role: anon</code>. Designed to ship to the browser. Every visitor of your app holds it.</li>
  <li><strong><code>service_role</code></strong> — a JWT with <code>role: service_role</code>. <strong>Bypasses RLS entirely.</strong> Must stay server-side (any backend — Node, Python, Edge Function, etc.).</li>
</ul>

<p>Once a user logs in, their browser presents a third JWT signed by Supabase Auth that includes their <code>sub</code> (user ID). That's the value <code>auth.uid()</code> reads inside RLS policies.</p>

<p>All requests hit the same PostgREST endpoint. What the database returns depends entirely on which JWT is presented and what RLS policies say about it.</p>

<h2>What RLS actually controls</h2>

<p>RLS = Row Level Security, a Postgres feature (not a Supabase invention). For each table you can:</p>

<ul>
  <li><strong>Disable RLS entirely</strong> — any role with <code>SELECT</code> grant on the table reads everything. The Supabase <code>anon</code> role has <code>SELECT</code> on everything in <code>public</code> by default.</li>
  <li><strong>Enable RLS with no policies</strong> — the default-deny state. Even the table owner reads nothing through RLS. (<code>service_role</code> still bypasses.)</li>
  <li><strong>Enable RLS + one or more policies</strong> — each policy is a SQL expression that filters rows visible to a given role/operation. Common: <code>CREATE POLICY "owner_read" ON x FOR SELECT USING (auth.uid() = owner_id);</code></li>
</ul>

<p>Two failure modes, both common:</p>

<ol>
  <li><strong>RLS off.</strong> Every table row is anon-readable.</li>
  <li><strong>RLS on, permissive policy</strong> like <code>USING (true)</code>. Same effect — every row is anon-readable.</li>
</ol>

<h2>Why "the default" is more nuanced than you'd think</h2>

<p>Two ways to create a table in Supabase:</p>

<ul>
  <li><strong>Dashboard → Table Editor.</strong> The "Enable Row Level Security" checkbox defaults to <em>checked</em> (since 2024). You'll get RLS-on with no policies — table is locked by default until you add a policy. This is the safe path.</li>
  <li><strong>SQL Editor / migrations / CLI <code>supabase db push</code>.</strong> Plain <code>CREATE TABLE</code> statements get RLS-off, like vanilla Postgres. The dashboard shows a yellow warning banner once it notices, but the table is exposed in the meantime.</li>
</ul>

<p>AI assistants — Lovable, Bolt, v0, Cursor with Supabase MCP — overwhelmingly go through the SQL path because that's what they're trained to write. So the apps we scan, which are predominantly AI-scaffolded, end up with the SQL-path default: RLS off.</p>

<h2>The failure is per-table, not per-project</h2>

<p>The pattern we see most often: a developer follows the official "build a Twitter clone" tutorial, enables RLS on the <code>profiles</code> table when prompted, writes a couple of policies. They internalize "I've configured RLS." Three months later they (or their AI assistant) add <code>invoices</code>, <code>customer_contacts</code>, <code>subscription_history</code> tables via SQL — RLS off, no policies, anon-readable.</p>

<p>One real example from our last batch: an app with <code>profiles</code> RLS-gated correctly, but 11 other tables added later — all wide open. Customer emails, account passwords (in a literal column), booking requests with phone numbers, chat messages.</p>

<h2>Three concrete fixes</h2>

<h3>1. The "every new table" habit</h3>

<p>If you write SQL by hand, make this the snippet you reach for:</p>

<pre><code>CREATE TABLE x (id bigint primary key, owner_id uuid, ...);

ALTER TABLE x ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner_can_select" ON x
  FOR SELECT USING (auth.uid() = owner_id);
CREATE POLICY "owner_can_modify" ON x
  FOR ALL USING (auth.uid() = owner_id);</code></pre>

<p>The ALTER + 2 policies are the minimum viable scaffold. Adjust the predicate per table.</p>

<h3>2. A pre-deploy lint</h3>

<p>Add a CI check that fails the build if any public-schema table has RLS off. Run this against your migration's resulting state, not against prod:</p>

<pre><code>SELECT n.nspname, c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname = 'public'
  AND c.relrowsecurity = false;</code></pre>

<p>Empty result = pass. Any rows = fail the build with the offending table names.</p>

<h3>3. Continuous external scan</h3>

<p>The CI check catches new tables before deploy. An external scan catches drift after deploy — schema migrations, manual SQL, third-party functions. We do this for free on one target; the paid plans run it weekly and email you if anything new broke.</p>

<h2>The platform fix</h2>

<p>If you're a Lovable / Bolt / Cursor template author or work on the Supabase team: surface the check above when an AI scaffold creates a new table via SQL. Five milliseconds of work, would prevent more critical disclosures than any single change in the AI-tooling ecosystem right now. The friction is purely social — devs see a "Enable RLS now?" prompt, click yes, write a policy. Don't ship.</p>

<p>The ecosystem will fix this eventually. Until then, scan before you launch.</p>
""",
    },
    {
        "slug": "anthropic-key-leaked-case-study",
        "title": "When your Anthropic key leaks: a case study",
        "date": "2026-04-12",
        "tag": "Case study",
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

<p>Our <code>secret-scan</code> module fetches the app's homepage, extracts <code>&lt;script src="..."&gt;</code> references (up to 3), downloads each bundle (up to 5 MB), and runs ~38 provider-specific regexes against the combined corpus. The Anthropic pattern is <code>sk-ant-api\\d+-[0-9A-Za-z_\\-]{80,}</code>. When it matches, severity is CRITICAL automatically.</p>

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


def reading_time(html: str) -> int:
    """Public alias of _reading_time."""
    return _reading_time(html)

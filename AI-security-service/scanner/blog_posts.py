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
        "slug": "1630-vulnerable-apps-855-no-contact-path",
        "title": "We scanned 5,850 web apps. 1,630 had critical issues. 855 of them have nowhere to receive a security report.",
        "date": "2026-05-06",
        "tag": "Findings",
        "excerpt": (
            "1,630 web apps have at least one critical or high-severity vulnerability. "
            "We tried to disclose every one of them. After exhausting Apollo, HTML scraping, "
            "WHOIS, DNS SOA, security.txt, and GitHub profile lookups, we can reach 775 owners. "
            "The other 855 are deployed on platforms that route the public to the app but hide "
            "the developer. There is no inbox to put a security report into."
        ),
        "body": """
<p>This week we ran our biggest scan yet. 6,194 web apps queued, 5,850 successfully fingerprinted, 1,630 with at least one CRITICAL or HIGH finding. 159 had a CRITICAL. 1,471 had a HIGH but no CRITICAL. The rest had only MEDIUMs or were clean.</p>

<p>The vulnerability mix was not surprising. Open admin panels, login endpoints with no rate limiting, Supabase tables with row-level security disabled, payment webhooks that accept unsigned events, hardcoded API keys baked into the JS bundle. The same playbook that has been broken for a decade.</p>

<p>That is not the story. The story is what happened when we tried to email all 1,630.</p>

<h2>The findings, briefly</h2>

<p>Most of the HIGH severity total comes from auth issues. 3,162 of our 5,094 CRITICAL+HIGH findings live in the auth bucket. Some patterns from the batch:</p>

<ul>
<li><strong>1,646 login endpoints with no rate limiting.</strong> /login, /api/login, /auth/login, /api/auth/signin. We send 10 POSTs in 200ms. Status codes are all 401, no slow-down, no captcha, no lockout. Try a million passwords.</li>
<li><strong>1,398 admin panels reachable without auth.</strong> /admin, /admin/dashboard, /panel, /internal, /wp-admin, /phpmyadmin, /_admin. Public to anyone who guesses the path.</li>
<li><strong>252 Supabase databases with broken row-level security.</strong> Anonymous reads or writes on tables holding user data. We have written about this one before.</li>
<li><strong>130 webhook endpoints that accept fake payment events.</strong> POST a checkout.session.completed without the signature header, get a 200 back. We blogged about that one yesterday.</li>
<li><strong>55 API keys hardcoded in JS bundles.</strong> View source, grep for "key=" or "Bearer ". Use the key. Rate limit hits the company's bill, not yours.</li>
<li><strong>184 endpoints leaking version, debug, or stack-trace info.</strong> /redoc, /swagger-ui.html, /api/debug/, verbose error pages.</li>
</ul>

<p>None of this is novel. Every line above is the same finding we file at every customer. The reason we keep filing it is that no one is fixing it at the population level.</p>

<h2>Trying to tell anyone</h2>

<p>Standard responsible disclosure: find a contact, email them with the finding, give them 90 days. We use a multi-stage pipeline because we have 1,630 apps to work through, not 1.</p>

<p><strong>Stage 1: existing pool.</strong> We had emails on file for 185 of the 1,630 affected hosts from prior scans. 11.4%.</p>

<p><strong>Stage 2: Apollo.</strong> For the 1,012 unenriched custom domains, we tried Apollo's people-search API. Apollo claims 100M+ professionals indexed. They returned exactly zero contacts for any of the 351 domains we queried (351 because the rest had findings but were on platform subdomains where org-domain enrichment does not apply). These apps are too small or too new to appear in any sales database.</p>

<p><strong>Stage 3: scrape the app itself.</strong> We pulled the homepage, /about, /contact, /imprint, /privacy, /team, /humans.txt for each of the 661 platform-subdomain hosts. Looked for mailto: links, footer text, and email patterns inside the JS bundle. 124 hits, about 19% of platform-subdomain apps embed an author email somewhere on the page. The other 81% don't.</p>

<p><strong>Stage 4: DNS and registrar lookups.</strong> For the 351 unenriched custom domains, we tried DNS SOA rname (the responsible-person email in the DNS authoritative record), WHOIS Registrant Email, /.well-known/security.txt, and /humans.txt. 33 total hits. Most WHOIS records are GDPR-redacted. Most DNS SOA rname fields point at the cloud provider (awsdns-hostmaster@amazon.com, msnhst@microsoft.com), not the developer. Most apps don't ship a security.txt.</p>

<p><strong>Stage 5: GitHub profile.</strong> Some apps link to a github.com/&lt;user&gt; URL in the footer. We pulled the user's public profile and checked for a public email. 4 hits, of 50 GitHub API calls (we capped to stay under unauth rate limits).</p>

<p>Final tally for this batch: 326 newly-found contacts plus the 185 we already had plus 264 we had emailed in earlier rounds equals 775 reachable affected hosts. <strong>The other 855 have no working channel.</strong> 695 are platform subdomains. 160 are custom domains where every channel returned nothing.</p>

<h2>The platform-subdomain problem</h2>

<p>Of the 855 we cannot contact, 695 are deployed on multi-tenant hosting platforms. The breakdown is illuminating:</p>

<table style="width:100%;max-width:480px;border-collapse:collapse;margin:20px 0;font-size:0.9rem;">
<tr><th style="text-align:left;padding:8px 12px;border-bottom:1px solid #1f2937;color:#9ca3af;font-weight:600;">Platform</th><th style="text-align:right;padding:8px 12px;border-bottom:1px solid #1f2937;color:#9ca3af;font-weight:600;">Affected hosts</th></tr>
<tr><td style="padding:6px 12px;">lovable.app</td><td style="text-align:right;padding:6px 12px;">142</td></tr>
<tr><td style="padding:6px 12px;">streamlit.app</td><td style="text-align:right;padding:6px 12px;">119</td></tr>
<tr><td style="padding:6px 12px;">onrender.com</td><td style="text-align:right;padding:6px 12px;">93</td></tr>
<tr><td style="padding:6px 12px;">replit.app</td><td style="text-align:right;padding:6px 12px;">74</td></tr>
<tr><td style="padding:6px 12px;">herokuapp.com</td><td style="text-align:right;padding:6px 12px;">57</td></tr>
<tr><td style="padding:6px 12px;">azurewebsites.net</td><td style="text-align:right;padding:6px 12px;">51</td></tr>
<tr><td style="padding:6px 12px;">railway.app</td><td style="text-align:right;padding:6px 12px;">49</td></tr>
<tr><td style="padding:6px 12px;">vercel.app</td><td style="text-align:right;padding:6px 12px;">43</td></tr>
<tr><td style="padding:6px 12px;">netlify.app</td><td style="text-align:right;padding:6px 12px;">41</td></tr>
<tr><td style="padding:6px 12px;">firebaseapp.com</td><td style="text-align:right;padding:6px 12px;">38</td></tr>
<tr><td style="padding:6px 12px;">fly.dev</td><td style="text-align:right;padding:6px 12px;">34</td></tr>
<tr><td style="padding:6px 12px;">appspot.com</td><td style="text-align:right;padding:6px 12px;">25</td></tr>
<tr><td style="padding:6px 12px;">bolt.host</td><td style="text-align:right;padding:6px 12px;">19</td></tr>
<tr><td style="padding:6px 12px;">deno.dev</td><td style="text-align:right;padding:6px 12px;">8</td></tr>
<tr><td style="padding:6px 12px;">workers.dev</td><td style="text-align:right;padding:6px 12px;">5</td></tr>
</table>

<p>Each of these platforms gives developers a free or low-friction way to ship an app. That is great. None of them gives a security researcher a route to the app's owner. There is no <code>/.well-known/contact</code>, no per-app security email, no &quot;report a security issue&quot; link in the platform-supplied footer, no way to ask the platform to forward a message to the developer. The platforms have a security@ for issues with the platform itself, but not for issues with apps running on top of it.</p>

<p>The result: a developer can ship an app on Lovable or Streamlit or Replit, expose 17 critical Supabase RLS misconfigurations to the public internet, and we have no way to tell them. Their users are at risk. The developer often does not know it. The platform sees the traffic but does not act because the platform's terms-of-service does not put them in the loop on individual app vulnerabilities.</p>

<h2>What should change</h2>

<p>Hosting platforms should add a per-app security contact channel. The bar is low.</p>

<p><strong>Minimum:</strong> when a security researcher visits <code>https://&lt;app&gt;.lovable.app/.well-known/security-contact</code>, the platform returns a tokenized email address that forwards to whichever account deployed the app. The token can rotate. The address can rate-limit. The app owner can opt out. None of that requires the platform to expose the developer's identity. It just requires that messages to that address get to the right human.</p>

<p><strong>Better:</strong> the platform's deploy UI prompts new users for a security contact email at sign-up, and the platform serves a generated <code>security.txt</code> at the app's apex with that email. Most platforms already prompt for billing email and notification email. One more field.</p>

<p><strong>Best:</strong> the platform runs its own automated scan against new deploys and surfaces findings in the developer's dashboard before anyone else can find them. We would be out of a job for that segment, which is fine.</p>

<p>Until something like this exists, half of the security issues we find on hosted-platform apps are going to stay shipped. We will keep scanning, we will keep enriching, we will keep emailing the ones we can. For the 855 we cannot reach this round, we are open to suggestions.</p>

<h2>Notes on method</h2>

<p>The 5,850 figure is targets that completed at least one full scan run. The other 344 in the input list either failed DNS, refused all requests, or 5xx'd through the entire scan window. Our affected count of 1,630 is unique hosts with at least one finding in CRITICAL or HIGH after a 16-module sweep that includes auth-bypass, supabase-audit, payment-bypass, openapi-audit, secret-scan, login-bruteforce, admin-panel, and the rest.</p>

<p>If you are running an app on one of the platforms above and you are wondering whether your app is in the unreachable 855, run the scanner: <a href="https://securityscanner.dev/" style="color:#dc2626;">securityscanner.dev</a>. It is free for the first scan. If you want a contact channel set up for your platform, email <a href="mailto:stefan@securityscanner.dev" style="color:#dc2626;">stefan@securityscanner.dev</a>.</p>
""",
    },
    {
        "slug": "stripe-webhook-signature-bypass-1500-apps",
        "title": "We probed 6,000 web apps for Stripe webhook signature checks. 1,542 don't bother.",
        "date": "2026-05-05",
        "tag": "Findings",
        "excerpt": (
            "A fake Stripe event in a curl one-liner. No Stripe-Signature header. "
            "1,542 of the apps we scanned this week returned a 200. That means anyone "
            "can forge payment events on those endpoints. Here is what we found and "
            "the six-line fix."
        ),
        "body": """
<p>Last week we scanned roughly 6,000 web apps with our payment-bypass module. The module is dumb on purpose. It POSTs a minimal fake <code>checkout.session.completed</code> event to a list of common webhook paths and asks one question: does the server accept it without a <code>Stripe-Signature</code> header?</p>

<p><strong>1,542 apps said yes.</strong></p>

<p>That is not a typo. One in four apps with a payment-webhook-shaped URL is willing to process a forged Stripe event from any HTTP client on the internet. No auth, no signature, no replay protection.</p>

<h2>What we actually sent</h2>

<p>The payload is whatever Stripe's documentation says a real event looks like, minus the cryptographic proof:</p>

<pre style="background:#0a0e17;color:#e5e7eb;padding:14px 16px;border-radius:8px;font-size:13px;overflow-x:auto;"><code>POST /api/webhook/stripe HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "id": "evt_secprobe_test",
  "object": "event",
  "type": "checkout.session.completed",
  "data": {
    "object": {
      "id": "cs_secprobe_test",
      "payment_status": "paid",
      "amount_total": 100,
      "customer": "cus_secprobe",
      "currency": "usd"
    }
  },
  "livemode": false
}</code></pre>

<p>That is it. No <code>Stripe-Signature</code> header. A real Stripe event arrives with a header that looks like <code>t=1234567890,v1=hexdigest...</code>, computed by Stripe using a secret you set up when you registered the webhook endpoint. If your server skips the signature check, it has no way to know whether the event came from Stripe, from us, or from anyone with curl.</p>

<p>We tried 17 common path variants per host: <code>/api/webhooks/stripe</code>, <code>/api/webhook/stripe</code>, <code>/api/payments/webhook</code>, <code>/webhooks/stripe</code>, plus the same patterns for Paddle and LemonSqueezy. If the server returned 200, 201, or 202, we counted it.</p>

<h2>The exploit primitive</h2>

<p>Why this matters more than a generic "missing auth" finding: Stripe webhooks are how payment status reaches the application. A typical SaaS flow looks like this:</p>

<ol>
<li>User clicks "subscribe", redirects to Stripe Checkout.</li>
<li>User pays. Stripe redirects them back.</li>
<li>Stripe also sends a <code>checkout.session.completed</code> webhook to your server.</li>
<li>Your server reads the event, looks up the customer email or session ID, and flips that user's account from <code>plan: free</code> to <code>plan: pro</code>.</li>
</ol>

<p>If step 4 doesn't verify the signature, anyone can fire step 4 directly. They sign up for the free tier, find the webhook URL (often documented or trivially guessable), and POST a fake event with their own customer ID. Their account upgrades. Stripe never charged them.</p>

<p>The variant that hits hardest: apps that look up the user from a field inside the event body (the customer email or session ID). The attacker doesn't even need a session, just the URL. Stuff their email in the fake event, hit send, get pro.</p>

<h2>Why is this so common?</h2>

<p>Stripe's documentation is good and the example code includes the signature check. Every major framework has a one-line library function for it. Yet a quarter of webhook endpoints we scanned don't run it.</p>

<p>The pattern we keep seeing in the developer journey:</p>

<ol>
<li>Build the integration locally with a stub handler that just <code>console.log</code>s the event body. Get the upgrade-the-user logic working. Signature verification is on the TODO.</li>
<li>Deploy to production. The signature check is still on the TODO.</li>
<li>It works. Real Stripe events come through. Customers pay, accounts upgrade. The TODO stays.</li>
<li>Six months later, no one remembers it was ever a TODO.</li>
</ol>

<p>The same pattern shows up on apps generated by code assistants. The generated route handler accepts JSON, parses the event, calls the upgrade function. Signature verification is a separate idea the developer has to remember to ask for. Most don't.</p>

<h2>Spread by hosting platform</h2>

<p>The 1,542 hits aren't concentrated on any one platform. Roughly half are on custom domains (production SaaS apps), half on hosted preview platforms. A few buckets:</p>

<ul>
<li>Custom domains: ~720 hits</li>
<li>Render (<code>onrender.com</code>): 198</li>
<li>Vercel: 142</li>
<li>Replit: 121</li>
<li>Railway: 87</li>
<li>Fly.dev: 64</li>
<li>Heroku: 58</li>
<li>Lovable, Bolt, Netlify, others: ~150 combined</li>
</ul>

<p>Custom-domain SaaS apps are the most worrying bucket because they are real businesses with real Stripe accounts. The hosted-preview hits are usually less serious. Many are demo apps, half-built side projects, or test deployments. But they still expose the same code patterns the developer will copy into production.</p>

<h2>One anonymized example</h2>

<p>One of the cleanest hits was a hotel booking site on Render. Their webhook endpoint at <code>/api/webhook/paddle</code> returned <strong>200 OK</strong> with an empty body to our forged event. The body told us nothing, but the 200 told us everything: the server accepted, parsed, and presumably acted on a Paddle event we made up.</p>

<p>We didn't follow up to confirm the exploit (sending a real fake-customer payload would cross from "scanning" to "actively defrauding"), but the primitive is clear. A guest could craft an event that says "this booking is paid", POST it, and the booking record flips to confirmed. The hotel sees a confirmed reservation in their dashboard. The guest never paid.</p>

<p>We disclosed to the operator privately. They acknowledged within 4 hours.</p>

<h2>The six-line fix</h2>

<p>Stripe's library does this for you. In Node:</p>

<pre style="background:#0a0e17;color:#e5e7eb;padding:14px 16px;border-radius:8px;font-size:13px;overflow-x:auto;"><code>app.post('/api/webhook/stripe',
  express.raw({type: 'application/json'}),
  (req, res) =&gt; {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body, sig, process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    // proceed with event
    res.json({received: true});
  });</code></pre>

<p>Same pattern in Python with the official <code>stripe</code> SDK, in Ruby, in Go, etc. Three things you need:</p>

<ol>
<li>Read the <code>Stripe-Signature</code> header.</li>
<li>Pass the <strong>raw</strong> request body, not the parsed JSON. Most frameworks parse JSON by default, which destroys the signature. You typically need to register a special body reader on the webhook route.</li>
<li>Get your webhook secret from the Stripe dashboard (Developers, Webhooks, click your endpoint, "Signing secret"). Stash it in <code>STRIPE_WEBHOOK_SECRET</code>.</li>
</ol>

<p>The middle step is where most people trip up. Express's default <code>express.json()</code> middleware will eat the raw body before your handler sees it, leaving Stripe's library to compute a signature against the parsed-and-stringified JSON, which never matches. The fix is to register <code>express.raw({type: 'application/json'})</code> just on the webhook route, before any global JSON parser. FastAPI users: read <code>await request.body()</code> directly, not <code>request.json()</code>.</p>

<p>Paddle, LemonSqueezy, and most other payment processors have the equivalent in their SDKs. If you are integrating any of them, the rule is: <strong>verify the signature before doing anything else with the payload</strong>.</p>

<h2>Caveats and methodology</h2>

<p>Two things worth being honest about.</p>

<p>First, a 200 response doesn't prove the application actually grants the user something on the back of the forged event. Some endpoints log every webhook for analytics and return 200 regardless. Others queue the event for async processing and return 200 immediately, then drop it later when validation fails. We can't know without exploiting, which we don't do. The 1,542 number is "endpoints accepting unsigned events", not "endpoints definitely upgrading the attacker's account".</p>

<p>Second, the 6,000 base for the percentage is the number of distinct hosts we scanned where at least one of the 17 webhook paths matched. Many apps don't have a webhook endpoint at all (no Stripe integration), so they aren't in the denominator.</p>

<p>What is irrefutable: 1,542 specific hosts have a payment-webhook-shaped URL that handles unsigned events with a 2xx response. That is a misconfiguration on its own, regardless of downstream behavior.</p>

<h2>Scan your own app</h2>

<p>The full payment-bypass module is part of our standard scan. Run it on your URL at <a href="/">securityscanner.dev</a>. It hits all 17 webhook path variants and tells you exactly which ones return 200 to an unsigned event. Three minutes, free, no signup required for the quick scan.</p>

<p>If you find your endpoint flagged, the fix is in the snippet above. If your stack isn't represented in the snippet, search for "[your stack] stripe webhook signature verification". Every framework has the canonical example.</p>
""",
    },
    {
        "slug": "beyond-supabase-rls-five-other-crits",
        "title": "Beyond Supabase RLS: 5 other critical vulnerabilities we found in 1,000 vibe-coded apps",
        "date": "2026-04-24",
        "tag": "Findings",
        "excerpt": (
            "Supabase RLS is the headline, but it's not the only thing breaking. "
            "We found IDOR endpoints leaking health records, OpenAI keys burning money in public JS bundles, "
            "entire APIs with zero auth, and private key material shipped to production. Here are 5 non-RLS "
            "finding classes from our 1,000-app scan."
        ),
        "body": """
<p>We just finished scanning 1,003 vibe-coded apps across Lovable, Bolt, Replit, Vercel, Streamlit, Heroku, and others. The Supabase RLS story is well-documented by now — 7.4% of Lovable apps and 6% of Bolt apps have tables wide open. But RLS accounted for 183 of our 190 CRITs. The other 7 came from finding classes that are arguably worse, because they're harder to detect and easier to exploit.</p>

<h2>1. IDOR with PII leaks — health records accessible by incrementing an ID</h2>

<p>Two Replit apps had Insecure Direct Object Reference (IDOR) vulnerabilities on their API endpoints:</p>

<ul>
<li><code>roti-mami-booking.replit.app</code> — <code>GET /api/bookings/{id}</code> returns any user's booking details (name, phone, email, appointment time) by iterating the numeric ID. No auth check.</li>
<li><code>data-trade-marketplace-1-russellmxavier.replit.app</code> — <code>GET /api/privacy-health/{id}</code> returns health-related records. The endpoint name alone tells you this shouldn't be public.</li>
</ul>

<p>IDOR is consistently one of the top finding categories in real-world bug bounties (broken access control tops the OWASP Top 10 and HackerOne's annual reports) and it's the easiest to exploit: change <code>/bookings/1</code> to <code>/bookings/2</code>. No tools, no Supabase knowledge, just a browser.</p>

<p>Why vibe-coded apps are especially vulnerable: AI code generators create CRUD endpoints with sequential IDs and no authorization middleware by default. The developer tests with their own data, sees it works, and deploys. They never test "what happens if I request someone else's ID" because the AI didn't generate that test either.</p>

<h2>2. OpenAI project keys in public JS bundles — real money at risk</h2>

<p>Two Bolt.host apps shipped live OpenAI <code>sk-proj-*</code> keys in their <code>/assets/index-*.js</code> bundles:</p>

<ul>
<li><code>crypto.bolt.host</code> — OpenAI project key in the Vite-built JS bundle</li>
<li><code>social-media-content-6eme.bolt.host</code> — same pattern</li>
</ul>

<p>Both returned 403 at time of writing (possibly already taken down or access-restricted). But the pattern is widespread: our <code>ai-js</code> module flagged <strong>38 apps across all platforms</strong> with hardcoded API keys in their JS bundles — 17 on Bolt.host (1 in 15), 18 on Vercel (1 in 4 of the AI-generated ones we scanned), and 3 others.</p>

<p>The risk is direct financial: anyone who extracts the key can make API calls on the owner's account. OpenAI bills per token. A single leaked key powering a GPT-4 loop can burn hundreds of dollars overnight before the owner notices.</p>

<h2>3. Entire APIs with zero authentication</h2>

<p>Two apps exposed their full OpenAPI spec with no security scheme defined on any endpoint:</p>

<ul>
<li><code>chatbot-ai-mjs9.onrender.com</code> — 7 public API endpoints, no auth</li>
<li><code>openui.fly.dev</code> — 12 public API endpoints, no auth</li>
</ul>

<p>These aren't missing auth on one forgotten endpoint. The <code>components.securitySchemes</code> section of their OpenAPI spec is entirely empty. Every operation is callable by any HTTP client without a token, cookie, or API key.</p>

<p>This typically happens when a developer builds with FastAPI or Express, gets the API working locally, deploys it, and never adds the auth middleware because "I'll do that before launch." The AI assistant generates the routes but doesn't add <code>Depends(get_current_user)</code> unless specifically asked.</p>

<h2>4. Private key material in production JS</h2>

<p><code>veta-dashboard.herokuapp.com</code> ships what appears to be private key material (PEM-format) inside its static JS bundle at <code>/static/js/main.*.js</code>. This is the kind of thing that happens when a <code>.env</code> file or a config object containing a private key gets bundled by Webpack/Vite because the build process doesn't distinguish "server-only" from "client-safe" variables.</p>

<p>The fix is usually one line in your bundler config — <code>define: { 'process.env.PRIVATE_KEY': undefined }</code> — but the developer has to know the key is leaking first. Most don't check their production bundle.</p>

<h2>5. The hardcoded API key epidemic on Bolt.host</h2>

<p>This deserves its own section. Our <code>ai-js</code> module analyzes the main JS bundle of every scanned app and flags hardcoded secrets. Across 251 Bolt.host apps:</p>

<ul>
<li><strong>17 of 251 Bolt.host apps</strong> (6.8%) had at least one hardcoded API key in the JS bundle</li>
<li><strong>18 of 67 Vercel AI apps</strong> (26.9%) had the same — the highest rate of any platform</li>
<li>Most common: <code>api_key</code> patterns (Supabase anon keys are expected and filtered out; these are other services)</li>
<li>Also found: <code>bearer_token</code> values, service credentials, webhook secrets</li>
</ul>

<p>The root cause: both Bolt.new and v0.dev generate frontend code that calls APIs directly from the browser. When the developer pastes their API key into the prompt ("use my OpenAI key sk-proj-..."), the generator embeds it in the client code. There's no server-side proxy step in the default templates.</p>

<p>Notably, Lovable had <strong>zero</strong> ai-js findings in this batch. Their code generator appears to route API calls through server-side endpoints by default — a meaningful architectural difference that keeps secrets out of the bundle.</p>

<h2>What this means</h2>

<p>Supabase RLS gets the headlines because it's the most common single finding class. But the real story from this 1,000-app scan is that <strong>vibe-coded apps have systemic security gaps across every layer</strong>: authentication (IDOR), secrets management (API keys in bundles), authorization (unauthed APIs), and data protection (RLS). No single fix addresses all of these.</p>

<p>The common thread: AI code generators optimize for "does it work?" not "is it safe?" The developer's prompt doesn't include "add auth middleware to every endpoint" or "never embed API keys client-side" because those aren't functional requirements. The resulting code works perfectly in a demo and fails catastrophically in production.</p>

<h2>Scan your own app</h2>

<p>Enter your URL at <a href="/">securityscanner.dev</a> — the quick scan takes 10 seconds, no signup. For the full 50-module scan including IDOR probing, JS bundle analysis, and Supabase RLS audit: <a href="/signup">one free scan, no card</a>.</p>

<h2>Methodology</h2>

<p>1,003 targets sourced from certificate transparency logs and Google search across 9 platforms. All scans read-only. Every CRIT finding was verified reproducible before disclosure. Disclosures sent to all identifiable owners before publication.</p>

<p>Full per-platform breakdown: <a href="/blog/lovable-vs-bolt-vs-replit-rls">Lovable vs Bolt vs Replit →</a><br>
Aggregate stats: <a href="/reports/2026-q2">State of Vibe-Coded Security Q2 2026 →</a></p>
""",
    },
    {
        "slug": "lovable-vs-bolt-vs-replit-rls",
        "title": "Lovable vs Bolt vs Replit: who's leaking the most Supabase data?",
        "date": "2026-04-16",
        "tag": "Findings",
        "excerpt": (
            "We scanned 1,750+ apps — 1,000+ vibe-coded across nine platforms, "
            "plus 200 YC companies as a control. Zero CRITs on YC. 53 CRITs on the vibe-coded side. "
            "Here's the per-platform breakdown."
        ),
        "body": """
<p><em>Updated April 24 with data from our 1,000-app batch scan. Original post covered 226 apps; numbers below now reflect 1,750+ total scans across all batches.</em></p>

<p>We ran our scanner against 1,750+ deployed apps: over 1,000 vibe-coded (Lovable, Bolt, Replit, Vercel, Streamlit, Heroku, and others) plus 200 YC companies as a control group. Same scanner, same modules — what's the actual per-platform risk profile?</p>

<h2>The headline</h2>

<table style="width:100%;margin:16px 0;border-collapse:collapse;">
<thead><tr style="border-bottom:1px solid #1f2937;"><th align="left" style="padding:8px 4px;">Cohort</th><th style="padding:8px 4px;">Scanned</th><th style="padding:8px 4px;">With CRIT</th><th style="padding:8px 4px;">Rate</th></tr></thead>
<tbody>
<tr><td style="padding:6px 4px;">YC companies (W21 → F25)</td><td align="center">200</td><td align="center">0</td><td align="center">0%</td></tr>
<tr><td style="padding:6px 4px;">Lovable</td><td align="center">476</td><td align="center">34</td><td align="center">7.1%</td></tr>
<tr><td style="padding:6px 4px;">Bolt.host</td><td align="center">289</td><td align="center">21</td><td align="center">7.3%</td></tr>
<tr><td style="padding:6px 4px;">Replit</td><td align="center">194</td><td align="center">4</td><td align="center">2.1%</td></tr>
<tr><td style="padding:6px 4px;">Vercel (v0/AI)</td><td align="center">67</td><td align="center">2</td><td align="center">3.0%</td></tr>
<tr><td style="padding:6px 4px;">Streamlit</td><td align="center">90</td><td align="center">0</td><td align="center">0%</td></tr>
<tr><td style="padding:6px 4px;">Other (Heroku, Render, Fly, Netlify)</td><td align="center">53</td><td align="center">3</td><td align="center">5.7%</td></tr>
<tr style="border-top:1px solid #1f2937;"><td style="padding:8px 4px;"><strong>Vibe-coded total</strong></td><td align="center"><strong>1,169</strong></td><td align="center"><strong>64</strong></td><td align="center"><strong>5.5%</strong></td></tr>
</tbody></table>

<p>Every single CRIT in this batch was the same class of issue: Supabase Row Level Security disabled on tables backing real user data. Not a mix of vulnerabilities — one pattern, showing up again and again.</p>

<h2>Why Bolt.host and Lovable converge at ~7% while Replit stays at 2%</h2>

<p>Both products target the same developer with the same backend (Supabase). So why the gap?</p>

<p>Our read, from looking at the exposed apps' JS bundles: <strong>Bolt deployments are more often quick prototypes that never got productionized.</strong> The giveaway is in the hostnames — <code>trippy-duplicated-6mxq.bolt.host</code>, <code>mobile-liquid-glass-w7cb.bolt.host</code>, <code>ffo-paywallmobile-sa-65qs.bolt.host</code>. Those auto-generated slugs mean the dev clicked "deploy" once to share with a friend, then forgot about it. RLS was never in scope because the app was never serious.</p>

<p>Lovable apps are more often <em>named</em> — <code>ruth-prissman-coach.lovable.app</code>, <code>crmcoach.lovable.app</code>, <code>engagementsurvey.lovable.app</code>. They belong to someone. The rate is lower, but the consequences per leak are higher, because it's a live business with real paying customers on the other side.</p>

<h2>The table names tell you exactly how this happens</h2>

<p>Looking across the 51 world-readable tables in these 10 apps, the names are almost all tutorial-style. Generic primitives that appear on every Supabase "build-your-first-app" guide: <code>users</code>, <code>profiles</code>, <code>sessions</code>, <code>categories</code>, <code>subscriptions</code>, <code>comments</code>, <code>coaches</code>, <code>players</code>, <code>teams</code>.</p>

<p>Only two tables appeared in more than one app in our sample (<code>players</code> and <code>categories</code>, each in 2 apps) — everything else is unique to its app. But the <em>shape</em> of the names is the same everywhere. These are the names you get when you start from the Supabase docs, get RLS working on your first tutorial table (usually <code>profiles</code> or <code>todos</code>), then build 10 more tables without touching the RLS toggle again. The Supabase dashboard shows each new table in green whether RLS is on or off, which makes the error silent.</p>

<p>The fix on Supabase's side is a single default-flip: new tables with RLS on by default instead of off. The dashboard has had an opt-in for this for years, but the default remains off — which is what produces findings like these at scale.</p>

<h2>The worst apps we found</h2>

<p>Three stood out for sheer volume of exposed data:</p>

<ol>
<li><strong>ruth-prissman-coach.lovable.app</strong> — 15 tables world-readable. The app is a personal coaching site for a therapist in Israel. The exposed tables include <code>payment_methods</code>, <code>future_sessions</code>, <code>content_subscribers</code>, and <code>email_delivery_attempts</code>. Real paying clients, real PII.</li>
<li><strong>videozenithuygulamasi.lovable.app</strong> — 9 tables. Turkish live-streaming platform with <code>live_chat_messages</code>, <code>profiles</code>, <code>subscriptions</code>. Every chat message every user has ever sent is readable with one curl.</li>
<li><strong>crmcoach.lovable.app</strong> — 8 tables. Hebrew coaching CRM with <code>user_roles</code>, <code>coaches</code>, <code>sessions</code>, <code>session_summaries</code>. Plus <code>user_roles</code> is writable, so an attacker can grant themselves admin on any account by sending one INSERT.</li>
</ol>

<p>All three were emailed disclosures the morning after the scan. At the time of writing, none have responded yet; we'll update this post if/when they do.</p>

<h2>What YC got right</h2>

<p>Zero CRITs across 100 YC companies — W24, S24, F24, W25, S25, F25. That's a striking result and worth unpacking.</p>

<p>It's not that YC companies run fancier security programs. A few of the 100 we scanned are 3-person teams that started 8 months ago. But they've all been through YC's Bookface / office-hour culture where one of the first things you hear from other founders is "don't ship the anon key with RLS off." That kind of informal transmission — the thing a YC cohort gives you that a vibe-coder downloading the Lovable starter template doesn't — is what's actually protecting these apps.</p>

<p>The YC apps did have findings: missing security headers, exposed <code>/docs</code> endpoints, CORS misconfigurations. But nothing where an attacker could drop a curl and walk away with customer data. There's a real difference between "not perfectly hardened" and "catastrophically exposed," and this batch makes the gap quantitative.</p>

<h2>One embarrassment for StackBlitz</h2>

<p>In a small bit of irony: <code>buildwith.bolt.new</code> — the StackBlitz-owned admin console for their "Build with Bolt" workshop program — has the same RLS misconfiguration. Its <code>coupons</code> table is anon-readable AND anon-writable. That table appears to hold Bolt Pro redemption codes. Anyone can harvest the codes or insert new ones and redeem them.</p>

<p>We didn't disclose to StackBlitz security because this post is about pattern, not piling on. But it's a good illustration that the bug doesn't respect maturity — if it can hit the platform's own internal tool, it can hit yours too.</p>

<h2>What this means if you're shipping</h2>

<p>If you're building on Lovable, Bolt, or Replit with Supabase, the one thing to do today is audit <strong>every</strong> table in your project — not just the one from the tutorial:</p>

<pre><code>SELECT schemaname, tablename,
       CASE WHEN rowsecurity THEN 'ON' ELSE 'OFF' END AS rls
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY rowsecurity, tablename;</code></pre>

<p>Anything showing <code>OFF</code> needs:</p>

<pre><code>ALTER TABLE &lt;table&gt; ENABLE ROW LEVEL SECURITY;
CREATE POLICY "authenticated_only" ON &lt;table&gt;
  FOR SELECT USING (auth.uid() IS NOT NULL);</code></pre>

<p>Tighter policies are obviously better — this is the minimum. If you want to check the full attack surface of your app in one shot, <a href="/signup">run a scan</a>; one free, no card.</p>

<h2>Methodology</h2>

<p>Targets sourced from: certificate transparency logs (<code>*.lovable.app</code>, <code>*.bolt.host</code>, <code>*.replit.app</code>, <code>*.bolt.new</code>, <code>*.tempo.new</code>, <code>*.emergent.sh</code>) for the vibe-coded cohort; YC's public directory for the YC cohort. All 226 unique — no overlap with our previous 150-target batch.</p>

<p>Scanner: our standard full-scan module set (80+ checks including <code>supabase-audit</code>, <code>baas-detect</code>, <code>secret-scan</code>, <code>nuclei</code>, <code>subdomain-takeover</code>, <code>github-dork</code>, AI-triage).</p>

<p>Every CRIT was verified reproducible before disclosure — we re-ran the exact curl command the scanner used, confirmed a real row came back, and used that specific command in the disclosure email to the owner.</p>

<p>Runtime: ~4 hours wall time at 10 concurrent scans on a t3.2xlarge. Zero scan failures out of 226.</p>
""",
    },
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
<p>You point it at a URL. It runs 80+ modules against that URL in parallel — from classic ones like nmap + TLS audit + nuclei to the ones that matter for vibe-coded apps specifically:</p>

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
<p>When you scan an app, we run 80+ modules organized into 7 categories. Here's each one, what it looks for, and what severity it can produce.</p>

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
    {
        "slug": "your-vibe-coded-app-is-probably-violating-gdpr",
        "title": "Your vibe-coded app is probably violating GDPR right now",
        "date": "2026-04-27",
        "tag": "Research",
        "excerpt": (
            "We scanned 3,030 vibe-coded apps and found 120 with critical vulnerabilities. "
            "92 had user data (names, emails, phone numbers) readable by anyone. "
            "Under GDPR, every one of these is a reportable data breach. Under CCPA, consumers can sue directly."
        ),
        "body": """
<p>Last weekend we scanned 3,030 deployed apps built with Lovable, Bolt, Replit, Vercel, and Netlify. 120 of them (4%) had critical vulnerabilities. The legal exposure is worse than the technical one.</p>

<p>92 apps had Supabase tables with user data (profiles, registrations, orders, clients) readable by anyone with the public anon key. 3 more had API endpoints returning real PII without any authentication. 2 had payment webhooks accepting unsigned events.</p>

<p>Under current privacy law, every one of these is a potential violation with real financial penalties.</p>

<h2>What we found</h2>

<p>Our scanner ran 80+ modules against each app. 306 critical findings across 120 apps. Here's the kind of data that was exposed:</p>

<ul>
<li><strong>Newsletter subscriber emails</strong> on a math tutoring app, readable via the Supabase anon key</li>
<li><strong>16 financial clients</strong> with names, emails, and phone numbers on a net worth tracking app, accessible via <code>GET /api/contacts</code> with no auth</li>
<li><strong>18 client emails and 15 phone numbers</strong> on a personal trainer app</li>
<li><strong>Job applicant registrations</strong> with emails and phone numbers on a job board</li>
<li><strong>Restaurant orders and customer data</strong> on multiple food delivery apps</li>
<li><strong>User profiles with phone numbers</strong> on an editing platform</li>
<li><strong>Sales leads</strong> in a Firestore collection, readable by anyone without authentication</li>
</ul>

<p>None of these apps require authentication to access this data. A single <code>curl</code> command returns everything.</p>

<h2>GDPR: up to 20 million euros</h2>

<p>The EU's General Data Protection Regulation applies to any app that processes data of EU residents, regardless of where the developer is based.</p>

<ul>
<li><strong>Article 32</strong> requires "appropriate technical and organisational measures" to ensure security. An open Supabase table with no RLS is the opposite of appropriate.</li>
<li><strong>Article 33</strong> requires breach notification to the supervisory authority within <strong>72 hours</strong> of becoming aware. If you're reading this and your app is affected, the clock may have started.</li>
<li><strong>Article 34</strong> requires notification to affected individuals if the breach is "likely to result in a high risk." Leaked email addresses and phone numbers qualify.</li>
<li><strong>Article 83</strong> sets fines up to <strong>&euro;20 million or 4% of global annual revenue</strong>, whichever is higher.</li>
</ul>

<p>"I didn't know" is not a defense. The controller is responsible for security regardless of technical expertise. The regulation requires data protection by design and by default (Article 25). An AI-generated app with zero access controls fails this test by definition.</p>

<h2>CCPA: consumers can sue you directly</h2>

<p>California's privacy laws give consumers a private right of action for data breaches. Statutory damages of $100 to $750 per consumer per incident, no need to prove actual harm. $7,500 per intentional violation. Applies to any business that collects personal information of California residents.</p>

<p>The net worth tracking app we found had 16 records with real names, emails, and phone numbers. If any of those people are California residents, the statutory damages could reach $12,000 from a single unauthenticated API call. A class action could multiply that.</p>

<h2>20+ US states, Brazil, and counting</h2>

<p>Beyond California, 20+ US states now have comprehensive privacy laws: Texas, Florida, Oregon, Montana, Colorado, Connecticut, Virginia, and more. They all require "reasonable security measures." An app with no access controls on its user database fails every interpretation of "reasonable."</p>

<p>Brazil's LGPD carries fines up to 2% of revenue. One of the apps we found with exposed PII had Portuguese-language content and likely processes Brazilian user data.</p>

<h2>Why vibe-coded apps are uniquely exposed</h2>

<p>Traditional apps go through some version of security review before production, even if it's informal. Vibe-coded apps skip every checkpoint.</p>

<ol>
<li><strong>The AI optimizes for "it works."</strong> When you prompt "build me a fitness tracker with user accounts," the AI builds the CRUD, the UI, the routing, and ships with Supabase tables wide open. Nobody asked it about compliance.</li>
<li><strong>Supabase's anon key is designed to be public</strong>, but Row Level Security is opt-in. The AI doesn't enable it because the app works without it during development. By the time real users sign up, the vulnerability is in production.</li>
<li><strong>No privacy-by-design review happens.</strong> No DPO, no privacy impact assessment, no data processing agreement with Supabase. The app goes from prompt to deployed in an afternoon.</li>
<li><strong>The developer doesn't know what GDPR requires</strong>, and the AI doesn't tell them. When was the last time an LLM said "before we deploy, let's complete a Data Protection Impact Assessment"?</li>
<li><strong>No cyber liability insurance.</strong> Most vibe-coded apps are built by solo founders or small teams. A single GDPR complaint could cost more than the app will ever earn.</li>
</ol>

<h2>The scale</h2>

<p>We scanned 3,030 apps in one weekend. There are hundreds of thousands of vibe-coded apps deployed right now. Lovable alone has 8 million users. If our 4% critical rate holds across the ecosystem, that's tens of thousands of apps exposing user data in violation of privacy law.</p>

<p>Georgia Tech's Vibe Security Radar tracked 35 CVEs from AI-generated code in March 2026 alone, up from 6 in January. Every week, more apps go live without security review.</p>

<h2>The 72-hour clock</h2>

<p>Once you know your app has exposed personal data, you may have a legal obligation to report it. Under GDPR Article 33, the 72-hour notification clock starts when the controller "becomes aware" of the breach.</p>

<p>If you're running a vibe-coded app with Supabase, check your RLS policies right now. If any table with user data has RLS disabled, and any EU resident has used your app, you likely have a reporting obligation.</p>

<h2>How much risk are you actually at?</h2>

<p>Not every non-compliant app will get fined. Enforcement is risk-based and complaint-driven. Here's a realistic breakdown:</p>

<div style="background:#0f2d1a;border:1px solid #166534;border-radius:8px;padding:16px;margin:16px 0;">
<p style="margin:0 0 8px;"><strong style="color:#4ade80;">Low risk: hobby project / internal tool</strong></p>
<p style="margin:0;color:#a7f3d0;">No real users, no EU data, no commercial purpose. Technically non-compliant but regulators have bigger fish. Fix it before you launch publicly.</p>
</div>

<div style="background:#2d2400;border:1px solid #854d0e;border-radius:8px;padding:16px;margin:16px 0;">
<p style="margin:0 0 8px;"><strong style="color:#fbbf24;">Medium risk: early SaaS / side project with real users</strong></p>
<p style="margin:0;color:#fde68a;">Real people signed up, you have their emails. One angry user filing a complaint with their local DPA triggers an investigation. Fines are unlikely to be maximum, but the process is expensive and distracting. Most apps we scanned are here.</p>
</div>

<div style="background:#2d0a0a;border:1px solid #991b1b;border-radius:8px;padding:16px;margin:16px 0;">
<p style="margin:0 0 8px;"><strong style="color:#f87171;">High risk: B2B SaaS / scaling / processing sensitive data</strong></p>
<p style="margin:0;color:#fecaca;">Enterprise customers will ask for SOC 2, DPA, and privacy impact assessments. Health, finance, or education data has sector-specific rules on top of GDPR. A breach here means losing customers, not just paying fines. The therapist booking app, the financial client tracker, the personal trainer app we found — all in this tier.</p>
</div>

<p>Enforcement is real though. The EU issued <strong>&euro;2.1 billion in GDPR fines in 2025</strong>. The trend is more enforcement, not less, and regulators are starting to pay attention to AI-generated applications.</p>

<h2>Minimum viable GDPR: 8 things you can do in one hour</h2>

<p>You don't need a lawyer to get 80% compliant. Here's the practical checklist:</p>

<ol>
<li><strong>Enable Supabase RLS on every table.</strong> Open your Supabase dashboard &rarr; Authentication &rarr; Policies &rarr; enable RLS on each table. This is the single highest-impact fix. It takes 5 minutes and eliminates the most common critical vulnerability we find.</li>

<li><strong>Test your own API without auth.</strong> Open a terminal and run: <code>curl https://yourapp.com/api/users</code> — if it returns data, you have an auth bypass. Do this for <code>/api/contacts</code>, <code>/api/orders</code>, <code>/api/settings</code>, <code>/api/admin</code>. Add auth middleware to anything that responds.</li>

<li><strong>Add a consent checkbox to your signup form.</strong> Unchecked by default. Links to your privacy policy. Required to submit. This is your Article 6 legal basis (consent). Takes 2 minutes in your UI code.</li>

<li><strong>Add a privacy policy.</strong> It doesn't need to be written by a lawyer. It needs to accurately describe: what data you collect, why, who you share it with (Supabase, Stripe, etc.), how long you keep it, and how users can delete their data. Use a template from <a href="https://gdpr.eu/privacy-notice/" rel="nofollow">gdpr.eu</a> and customize it.</li>

<li><strong>Add a "delete my account" button.</strong> GDPR Article 17 requires it. When clicked, delete the user record and all associated data (scans, orders, profiles). Return confirmation. This can be a single API endpoint.</li>

<li><strong>Add a cookie banner.</strong> If you use session cookies for auth (you probably do), you need one. It doesn't need to be complex — "We use cookies for authentication. <a href="/cookies">Learn more</a>. [Accept]" is sufficient if you're not running tracking scripts.</li>

<li><strong>Check your webhook signatures.</strong> If you use Stripe, Paddle, or LemonSqueezy, verify the webhook signature before processing events. This is a security issue AND a compliance issue — accepting forged payment events means your transaction records are unreliable.</li>

<li><strong>Remove PII from your frontend bundle.</strong> Search your JS bundle for email addresses, API keys, and connection strings. They shouldn't be there. Use environment variables and server-side API calls.</li>
</ol>

<p>That's it. Eight steps, one hour, and you've addressed the most common violations we see in vibe-coded apps. None of these require a lawyer, a DPO, or a compliance consultant.</p>

<h2>Compliance as competitive advantage</h2>

<p>GDPR compliance isn't just about avoiding fines. It's a distribution advantage:</p>

<ul>
<li><strong>B2B sales.</strong> Enterprise customers require vendor security questionnaires, DPAs, and proof of compliance before signing. Having a privacy policy, data export, and account deletion already built puts you ahead of 90% of vibe-coded competitors.</li>
<li><strong>App store distribution.</strong> Apple and Google are tightening privacy requirements. A clear data handling story makes review easier.</li>
<li><strong>EU market access.</strong> 450 million consumers. If your competitor isn't GDPR-compliant and you are, you win that market by default.</li>
<li><strong>User trust.</strong> A "Delete my data" button and a clear privacy policy signal you take users seriously. That matters when you're a new, unknown app.</li>
</ul>

<h2>What we did to our own app</h2>

<p>After writing this article, we audited securityscanner.dev against the same checklist. We found gaps.</p>

<ul>
<li>No cookie consent banner. Fixed.</li>
<li>No data export endpoint. Added <code>GET /api/me/data-export</code>.</li>
<li>No account deletion. Added <code>POST /api/me/delete-account</code>.</li>
<li>Newsletter storing IP addresses unnecessarily. Removed.</li>
<li>No cookie policy page. Added <code>/cookies</code>.</li>
<li>Missing signup consent checkbox. Added.</li>
<li>Outreach emails missing physical address. Added.</li>
</ul>

<p>If a company that builds a security scanner had compliance gaps, your vibe-coded app almost certainly does too.</p>

<h2>Methodology</h2>

<p>We scanned 3,030 apps across Lovable (838), Bolt (917), Netlify (564), Vercel (448), Replit (223), and others (40). Each scan ran 80+ non-destructive modules including Supabase RLS probing (extracts table names from JS bundles, tests each with the anon key), authentication bypass testing, payment webhook verification, and PII exposure detection. All findings were verified with reproducible evidence. Responsible disclosures were sent to identifiable app owners.</p>

<p>Full results: <a href="/reports/2026-q2">Q2 2026 Security Report</a></p>
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

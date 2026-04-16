# Security Scanner — Go-to-Market Strategy

**Started:** 2026-04-16
**Owner:** Stefan
**Status:** Live document — expand continuously. Date-stamp additions.

---

## TL;DR

Security Scanner is 4 weeks old. Live product, $9 / $29 / $99 tiers, Stripe production, one free scan per signup. Current asset: 659 scans done, 20+ disclosures sent, 6 published blog posts, one identified positioning — *"security for the vibe-coding era."*

The next 4 weeks decide whether this becomes a real product or a solid side project. Primary lever: **HN launch Tuesday 2026-04-21**. Everything else is either preparing for that spike or capturing the tail.

---

## North-star goals

| Horizon | Metric | Target |
|---|---|---|
| 24 hours post-HN | Signups | 150–500 |
| 24 hours post-HN | HN front-page time | 4+ hours |
| 7 days post-HN | Paid conversions (any plan) | 8–15 |
| 30 days post-HN | MRR | $500 |
| 30 days post-HN | Organic (non-HN) signups/day | 10+ |
| 90 days post-HN | MRR | $2k |
| 90 days post-HN | Weekly active scanning (free+paid) | 200 |

These are our targets, not promises. The direction matters more than the exact numbers.

---

## Positioning

- **Who we are:** A security scanner for apps that ship with Cursor, Claude Code, Lovable, Bolt, Replit, v0 — "vibe-coded" apps built by devs who didn't grow up on OWASP. The scanner writes a `SECURITY-FIX.md` their AI assistant can execute.
- **Who we are NOT:** Snyk (dependency scanning), Burp Suite (interactive pen-testing), Cobalt (human pen-test engagement), Detectify (enterprise DAST). We're the 3-minute "scan the URL you just deployed" tool.
- **What makes us credible:** 20+ real disclosures, detailed blog posts with named apps, OpenAI responded to ours, StackBlitz's own admin panel was leaking. We find bugs, we tell owners quietly, we write about the pattern.

---

## Press & PR outreach

**Is it worth doing?** Yes. We have actual news, not a feature announcement:
1. **A quantifiable story:** 226-app batch, 7.9% of vibe-coded apps had CRIT, 0% of YC apps did.
2. **A spicy anecdote:** StackBlitz's own Bolt-Pro-coupons admin panel exposes its coupon table to anyone.
3. **A responsible narrative:** we disclosed every finding privately before writing anything public. That flips the story from "scanner startup names-and-shames" to "scanner startup follows responsible disclosure and shares the pattern."
4. **A human angle:** the worst app we found was a therapist's site with payment methods + therapy-session data world-readable. Real-world harm, not theoretical.

This is publishable. Not a front-page story, but a mid-tier security / dev-tools piece absolutely.

### Journalist target list

Pitch these **3–5 days before the HN submission** (Thurs/Fri 2026-04-17/18) with a soft embargo ("going public next Tuesday, happy to give you early access").

#### Tier 1 — security-beat journalists (best fit)

| Journalist | Outlet | Angle | Contact |
|---|---|---|---|
| **Lorenzo Franceschi-Bicchierai** | TechCrunch Security | AI-era dev-tools producing insecure apps | `lorenzo@techcrunch.com` · @lorenzofb |
| **Kim Zetter** | Independent / Zero Day newsletter | Worst-case user story (therapist's site), disclosure ethics | `kim@kimzetter.com` · zetter.com |
| **Joseph Cox** | 404 Media | StackBlitz leaking their own admin panel = great 404 story | `joseph@404media.co` · @josephfcox |
| **Andy Greenberg** | Wired | "Is vibe-coding a new vulnerability class?" framing | Via Wired desk · @a_greenberg |
| **Lawrence Abrams** | BleepingComputer | Deterministic, factual breakdown of the 226-batch findings | `lawrence.abrams@bleepingcomputer.com` |
| **Dan Goodin** | Ars Technica | Deep technical angle on the RLS default-off pattern | `dan@arstechnica.com` · @dangoodin001 |

#### Tier 2 — security-specialist outlets (likely pickups)

| Outlet | Best angle | How to pitch |
|---|---|---|
| **The Record** (Recorded Future) | Platform-level misconfig story | `tips@therecord.media` |
| **Dark Reading** | Tooling + technique deep-dive | Contact form |
| **SC Media** | Industry audience, will cover tools | `editorial@scmedia.com` |
| **SecurityWeek** | Enterprise lean but covers bug stories | Contact form |
| **The Register** | British angle + tech bite | `news@theregister.com` |

#### Tier 3 — dev/startup outlets

| Outlet | Angle | Contact |
|---|---|---|
| **The New Stack** | "Vibe-coded apps security" as a category-defining story | `editors@thenewstack.io` |
| **InfoQ** | Technical audience, good for the methodology post | Contact form |
| **TLDR Newsletter** | Wide reach — submit story via form | tldr.tech/submit |
| **Pointer** | Dev newsletter | suren@pointer.io |
| **Console** | Dev tools newsletter | console.dev |

#### Tier 4 — vibe-coding-adjacent / startup

| Publication | Angle |
|---|---|
| **Every** (Dan Shipper) | Vibe-coding thought-leader audience |
| **Lenny's Newsletter** | Low probability but huge if it lands |
| **The Pragmatic Engineer** (Gergely Orosz) | Dev career audience — could mention as aside |

### Pitch template (plain-text, personal)

```
Subject: Scanned 226 AI-generated apps — 10 are leaking user data right now

Hi [Name],

I'm Stefan, building Security Scanner (securityscanner.dev). We ran
226 deployed apps through our scanner this week — 126 built with
Lovable/Bolt/Replit/Cursor/Claude Code, plus 100 YC companies as a control.

Results:
- 10 vibe-coded apps have CRITICAL Supabase misconfigs RIGHT NOW
  (customer payment info, therapy sessions, private couples' pages)
- 0 of the 100 YC companies had a CRIT
- Including one StackBlitz-owned admin panel that leaks their own
  Bolt Pro coupon codes

We disclosed every finding privately to owners before publishing
anything. Full technical write-up is ready.

Launching next Tuesday on HN. Happy to give you early access to the
dataset and a pre-embargo walkthrough if you'd like to cover it.

Stefan
stefan@securityscanner.dev
https://securityscanner.dev/blog/lovable-vs-bolt-vs-replit-rls
```

Customize per journalist — Zetter gets the therapist-site lead, Cox gets StackBlitz, etc.

### Press follow-up cadence
- Send Thurs 2026-04-17 morning ET (journalists do their week's reading Thurs/Fri)
- 48-hour reply window. If no reply, single follow-up Sat evening.
- Don't spam. If they don't bite, don't chase past two touches.

---

## Content strategy — 4 weeks

### Week 0 (now → Mon Apr 20)
- ~~Write per-platform RLS comparison post~~ ✓ done
- ~~Mobile-optimize landing~~ ✓ done
- **Finalize HN_LAUNCH_CONTENT.md** with the chosen title + first-comment
- **Pre-write follow-up first-comment responses** for predictable HN questions:
  - "How do you differ from Snyk?" (Snyk = deps, we = deployed URL)
  - "Can I self-host?" (not today, hosted product for now)
  - "What if I scan someone else's app?" (ToS requires auth; we do read-only only)
  - "Are you open-source?" (not today, detection patterns are the product)

### Week 1 — HN Launch Week (Apr 21–27)
- **Tue 04-21 8:30am ET:** HN submission
- **Tue 04-21 8:31am ET:** first-comment, X thread (6 tweets), IndieHackers cross-post, pre-pinged friends DM link
- **Tue 04-21 10:00am ET:** email press list (Tier 1, 2) with "we just went live on HN, traction attached"
- **Wed 04-22:** reply to all HN comments from <24h window
- **Wed 04-22:** post a retrospective "what HN taught us" comment pinned to the thread
- **Thu 04-23:** post launch to r/programming + Lobsters
- **Fri 04-24:** X thread: "I DMed disclosure emails to 20 apps. Here's the 7 that fixed it." — real numbers, names (if they fixed).
- **Sat 04-25:** launch tweet: "3 days in, here's what we learned" — aggregate signups + CRITs caught
- **Sun 04-26:** weekly newsletter #1 goes out

### Week 2 — Search & Community (Apr 28–May 4)
- **Mon 04-28:** ship free tool #1: `/tools/supabase-rls-check` (paste anon key + URL, get yes/no)
- **Tue 04-29:** submit RLS comparison post to r/supabase with a tailored title
- **Wed 04-30:** cross-post top 2 blog posts to Dev.to + Hashnode (canonical URLs back)
- **Thu 05-01:** publish "Lovable security checklist" — 800 words, per-platform playbook
- **Fri 05-02:** Discord rounds — answer questions in Lovable, Bolt, Supabase communities (no spam, just value)
- **Sun 05-03:** weekly newsletter #2

### Week 3 — Programmatic SEO + Backlinks (May 5–11)
- **Mon 05-05:** ship free tool #2: `/tools/env-exposure-check` (enter URL → check common dotfile paths)
- **Tue 05-06:** publish "Bolt security checklist"
- **Wed 05-07:** disclosure-target outreach — contact the 7 we disclosed to successfully, ask if they'd link our post in their "security updates" page
- **Thu 05-08:** publish "Replit security checklist"
- **Fri 05-09:** X/LinkedIn thread re-using newsletter #2 content
- **Sun 05-10:** weekly newsletter #3

### Week 4 — Durability (May 12–18)
- **Mon 05-12:** ship free tool #3: `/tools/subdomain-takeover-check`
- **Tue 05-13:** publish "Supabase + Next.js security checklist"
- **Wed 05-14:** ship "security badge" widget (embeddable — "Scanned by Security Scanner")
- **Thu 05-15:** partner outreach email to Supabase DevRel (generic: "we help your users, add us to your security resources?")
- **Fri 05-16:** month-end report: "State of vibe-coded security: April 2026" — aggregate post at `/reports/2026-04`
- **Sun 05-17:** weekly newsletter #4

---

## Channels

### HN (biggest single lever — one shot)
- Title: `Show HN: I scanned 50 Lovable apps – 1 in 5 had Supabase wide open`
- URL: `/blog/top-5-supabase-rls-mistakes-on-lovable-apps`
- First comment immediately, pre-ping 3–5 HN-active friends for early upvotes + 1 substantive comment each
- Reply to every comment within 10 min for the first 2 hours
- **Don't delete negative comments** — respond honestly. HN punishes defensiveness.

### X / Twitter
- Thread on launch day (6 tweets, content in `HN_LAUNCH_CONTENT.md`)
- Weekly thread for ~4 weeks: findings from recent scans, screenshots of fix files
- Reply to mentions of "supabase rls", "subdomain takeover", "vibe coding security" in real time
- Don't buy followers / engagement pods. Slow-build is fine.

### LinkedIn
- Stefan has an existing Bitmovin network. One post per week with the blog post + "here's what's different from what you've seen before."
- Target audience: dev leadership, CTO types at startups — these are the people who buy the $99/mo plan.

### Reddit
- **r/supabase** — submit "1 in 20 Supabase+Lovable apps are leaking data" 4–5 days after HN
- **r/programming** — submit the launch the Thursday after HN
- **r/netsec** — post the technical RLS deep-dive (not the launch)
- **r/webdev** — platform-specific posts (Bolt, Replit checklists)
- **r/nextjs** — .env exposure + Supabase RLS tie-in
- Rule: never self-promote unless the post provides real value. Reddit mods are ruthless.

### Communities
- **Supabase Discord** — help in #general, mention scanner only when directly asked
- **Lovable Discord** — similar. Avoid looking like we're trolling their platform.
- **Bolt Discord** — same
- **Cursor Forum** — "security review" is a natural conversation
- **Claude.ai Discord** — we're MCP-compatible, perfect fit

### Newsletters we want to land in
- **TLDR Newsletter** (submit via form)
- **Pointer** (submit to `suren@pointer.io`)
- **Console** (via console.dev submission)
- **Sourcegraph's "Dev Digest"**
- **DevOps'ish**
- **The New Stack's weekly**
- **OffSecML** (AI security newsletter)

---

## Product-led growth

### Free tools (SEO magnets)
Each at its own URL, single-purpose, ranks for a specific search:

| URL | What it does | Primary search target |
|---|---|---|
| `/tools/supabase-rls-check` | Paste anon key + project URL → scan all tables | "supabase rls check", "check supabase security" |
| `/tools/env-exposure-check` | Enter URL → check for `/.env`, `/.git/config`, etc. | ".env exposure test", "is my .env public" |
| `/tools/subdomain-takeover-check` | Enter domain → check CNAMEs for dangling takeover risks | "subdomain takeover check" |
| `/tools/supabase-anon-key-decoder` | Paste a Supabase JWT → show scopes, anon vs service_role | "decode supabase jwt", "anon key vs service role" |
| `/tools/security-headers` | Enter URL → show present/missing headers with fix explanations | "security headers check" |

Each tool:
- Completes in < 10 seconds
- Shows clear pass/fail per finding
- "Run the full scan → [Signup]" CTA at the bottom
- Embeds directly into the main scanner — no duplicate code path

### Security badge widget
- Users who pass a scan clean can embed a badge: `<img src="https://securityscanner.dev/badges/pass/<hash>.svg">`
- Links back to us
- Free on Free plan (1 badge/month, auto-renewed per scan)
- Paid gets permanent badge + custom styling
- This is how Let's Encrypt got early traction. Badges are a backlinks farm.

### Public scan result pages (opt-in)
- Users can make a scan result publicly viewable at `/scan/<hash>` — great for bug bounty writeups, disclosure follow-ups
- Each public scan page = a backlink + a SEO-indexed page with findings

---

## Disclosure-driven traffic (our unique edge)

Every disclosure we send is a potential backlink / case study. Systematize it:

### Follow-up email 2 (after 30 days)
After a target fixes, we know because we can re-scan. Send:

```
Hi [name],

Quick follow-up on the disclosure I sent [date]. Re-scanned
[domain] today — issue is fully resolved.

We're publishing a quarterly "state of vibe-coded security" report
at securityscanner.dev/reports. Would it be OK to include your
remediation as a positive case study (linking to your site, e.g.
"the team at [X] fixed within 7 days of disclosure")? No
obligation — we can include you anonymously or not at all.

Happy to help anytime,
Stefan
```

Response rate estimate: 30% say yes with real-name link, 40% anonymous-OK, 30% decline/silent. 5–7 high-quality backlinks from this alone over the next 90 days.

### Positive public case studies
One blog post per notable remediation, written AFTER the company fixes + approves. Example:
- "How [X] fixed their Supabase RLS in 4 hours (and what they did right)"

---

## Partnerships

### Immediate targets (email this week)
| Partner | Why | Ask |
|---|---|---|
| **Supabase DevRel** (devrel@supabase.com) | We help their users; we're not competitive | Add us to their "security resources" page |
| **Cursor DevRel** | MCP-native; our `/security-scan` slash command | Featured as a community skill/MCP |
| **Claude team @ Anthropic** | We're an MCP server; they promote good MCPs | Listed on claude.ai MCP examples (if that exists) |
| **Stackblitz/Bolt** | We disclosed; show them we're constructive | Acknowledge us in their security docs |
| **Vercel** | We find subdomain takeovers on Vercel deployments | Partner via their ISV program |

### Long-term (post-launch)
- **Snyk** — adjacent but non-competitive. Joint content on "dependency scanning meets URL scanning."
- **HackerOne** — we're a private-disclosure channel. They might list us on "responsible researcher tools."
- **GitHub** — our `github-dork` module + secret-scan are natural integrations. Long shot.

---

## Paid (for reference — not priority)

If we hit a wall and want to kickstart:
- **Google Ads on specific long-tail**: "supabase rls check" $2–4 CPC, low volume. Budget: $200 test.
- **X ads targeted at Supabase community handles**: $500 test for a thread.
- **Sponsorship in TLDR Newsletter**: $1500/issue for a dev audience of 500k+. Only worth it if we have >$1k MRR first.

Don't start these until organic proves it's working.

---

## Metrics & cadence

### Weekly review every Sunday (15 min)
- Newsletter subscribers
- Daily signups (7-day rolling avg)
- Paid conversions YTD
- MRR
- Top traffic source last 7 days
- Top-ranked organic keyword
- Outbound emails sent + responses (disclosures, press, partners)
- Blog post published this week
- 1 thing that surprised me this week

### Dashboards to build
- `/admin/gtm-dashboard` (we should build this) — show the above in one view, DB-backed.
- Cloudflare Analytics → landing page pageviews, top referrers
- Resend → email send stats

---

## Ideas backlog (expand freely)

Add-below as things come up. Tag with the date and a 1-line rationale.

### Content ideas
- **2026-04-16** — "A day in the life of a vibe-coded app's anon key" — walk through the full attack chain from "I visit the app" to "I have the data"
- **2026-04-16** — Comparative post: "Lovable vs the others: the security story" (separate from the RLS piece)
- **2026-04-16** — "What OpenAI's disclosure response looked like" — case study of the one vendor that actually responded
- **2026-04-16** — Deep dive: "Why `profiles` is always the first exposed table" (Supabase tutorial ergonomics)

### Distribution ideas
- **2026-04-16** — Submit to **Console** / **Pointer** manually, tailored pitch
- **2026-04-16** — Find one open-source security-focused newsletter to guest-write for
- **2026-04-16** — Reach out to `tanay` / `mattxwang` / `dang` type HN power users *before* Tue — they know our space and may upvote naturally if interested

### Product ideas (drives GTM)
- **2026-04-16** — A `securityscanner.dev/audit-[domain]` public URL pattern that runs a lite scan and surfaces findings. SEO-indexed page per domain. Massive long-tail play.
- **2026-04-16** — Integration with Railway / Render / Fly.io post-deploy webhooks — "automatically scan every deploy"
- **2026-04-16** — Chrome extension that runs the `secret-scan` module on any page you visit

### Press ideas (to revisit monthly)
- **2026-04-16** — After 30 days, do a "state of vibe-coded security" report. Worth pitching as its own story.
- **2026-04-16** — If StackBlitz fixes `buildwith.bolt.new` quietly, we can publish the story in 60 days under responsible disclosure — that's a 404 Media piece
- **2026-04-16** — Conference talk pitches: O'Reilly Security (Oct), DEF CON Workshops, QCon. Not traffic, but credibility.

### Random
- **2026-04-16** — "Security-scanner-as-a-gift" — Mother's Day / Father's Day promotion ("give a security scan to your parents' small-business website"). Weird but memorable.

---

## What we're deliberately NOT doing (first 4 weeks)

- Paid ads (see: "proven organic first")
- YouTube (high effort, slow)
- Conference sponsorships (no ROI at this stage)
- Influencer deals
- SEO agencies / link-building services (Google penalizes)
- "Alternative to X" posts (too combative, wrong brand)
- Community spam (every post needs to stand on its own merit)

---

*Document started 2026-04-16. Update the "Ideas backlog" section freely. Rewrite the 4-week calendar as we learn.*

# Press Pitches — Security Scanner Research

Ready to send. Personalize the opener for each journalist, then copy-paste.

---

## Pitch A — Security/tech journalists (TechCrunch, Ars, Wired, 404 Media, BleepingComputer, The Register, Cybernews, The Record, SecurityWeek, The Hacker News)

**Subject:** Data: we scanned 1,764 vibe-coded apps — 453 critical vulnerabilities, 0 in YC companies

```
Hi [Name],

I'm Stefan, founder of Security Scanner (securityscanner.dev). We ran
the first large-scale security audit of apps built with AI coding tools
— Lovable, Bolt, Replit, Cursor, v0 — and the results are bad.

The numbers:
• 1,764 apps scanned across 9 platforms
• 453 critical findings — 7% of Lovable apps and 7% of Bolt apps
  have Supabase databases readable by anyone
• 200 YC companies scanned as control: 0% critical rate
• 15% of Bolt apps ship hardcoded API keys (OpenAI, Stripe, etc.)
  in public JS bundles
• 2 apps had IDOR vulnerabilities leaking health records and booking PII
• One app: a therapist's coaching site with 15 tables exposed including
  payment_methods and therapy session notes

We disclosed every finding privately before publishing. All data is at:
• Full report: https://securityscanner.dev/reports/2026-q2
• Per-platform breakdown: https://securityscanner.dev/blog/lovable-vs-bolt-vs-replit-rls
• Non-RLS findings: https://securityscanner.dev/blog/beyond-supabase-rls-five-other-crits

Happy to share the full dataset, walk through methodology, or jump on a
call. The scanner is live — anyone can verify our findings independently.

Stefan
stefan@securityscanner.dev
```

### Send to (copy subject + body, personalize first line):

| # | Name | Publication | Email / Contact | Personalize with |
|---|---|---|---|---|
| 1 | Zack Whittaker | TechCrunch | tips@techcrunch.com | "Saw your piece on [recent security story]" |
| 2 | Lorenzo Franceschi-Bicchierai | TechCrunch | tips@techcrunch.com | Health data angle |
| 3 | Dan Goodin | Ars Technica | @dangoodin on Mastodon | Technical deep-dive offer |
| 4 | Andy Greenberg | Wired | via Wired tips | "AI democratizes vulnerabilities" angle |
| 5 | Joseph Cox | 404 Media | via 404media.co/about | Therapist site / real people harmed |
| 6 | Lawrence Abrams | BleepingComputer | Signal: LawrenceA.11 | Classic vuln research framing |
| 7 | The Register | theregister.com | via tips page | "Extends your Apr 20 Lovable coverage with cross-platform data" |
| 8 | Cybernews | cybernews.com | via contact | "Extends your Lovable coverage with systematic data from ALL platforms" |
| 9 | Martin Matishak | The Record | martin.matishak@therecord.media | Data-driven research angle |
| 10 | Eduard Kovacs | SecurityWeek | @EduardKovacs on X | Vuln disclosure at scale |
| 11 | Ravie Lakshmanan | The Hacker News | ravie@thehackernews.com | OpenAI keys burning money angle |
| 12 | Brian Krebs | Krebs on Security | krebsonsecurity@gmail.com | Therapist PII / human impact |
| 13 | Patrick Gray | Risky Business | via risky.biz | Perfect news segment pitch |
| 14 | Kelly Jackson Higgins | Dark Reading | via darkreading.com | Enterprise risk / CISO angle |

---

## Pitch B — Business press (Bloomberg, WSJ, Business Insider, Reuters, Forbes)

**Subject:** AI coding tools shipping insecure apps at scale — first large-scale data

```
Hi [Name],

I'm Stefan, founder of Security Scanner. We just completed the first
large-scale security audit of applications built with AI coding tools
like Lovable, Bolt.new, and Replit — the "vibe coding" trend that's
taken off this year.

Key findings from scanning 1,764 deployed apps:
• 7% have databases that anyone can read without authentication
• 15% of Bolt.new apps ship API keys (OpenAI, Stripe) in public code
• A therapist's site exposed payment methods and session notes for
  every client
• A college system exposed student records
• Health booking apps leaked patient PII through basic URL manipulation
• Control group: 200 Y Combinator companies had 0% critical rate

This matters because millions of non-technical founders are using these
AI tools to build and deploy production apps handling real customer data.
The tools optimize for "does it work?" not "is it safe?"

Full data: https://securityscanner.dev/reports/2026-q2

Happy to discuss on background or provide the dataset for independent
verification.

Stefan Lederer
stefan@securityscanner.dev
securityscanner.dev
```

### Send to:

| # | Name | Publication | Contact | Angle |
|---|---|---|---|---|
| 15 | Bloomberg Tech | bloomberg.com | via tips (published vibe-coding Apr 5) | Security follow-up to their FOMO piece |
| 16 | Robert McMillan | WSJ | @bobmcmillan on X | Enterprise cyber risk |
| 17 | Business Insider | businessinsider.com | tips@businessinsider.com | "Your therapist's AI-built site may be leaking your notes" |
| 18 | Reuters Tech | reuters.com | via tips | Wire-service: first large-scale audit |
| 19 | Forbes | forbes.com | via contributor contact | Startup risk / AI liability |

---

## Pitch C — Developer/indie media (Simon Willison, TLDR, Changelog, newsletters)

**Subject:** 1,764 vibe-coded apps scanned — the security data

```
Hi [Name],

Built a scanner that audits deployed apps for the usual vibe-coding
mistakes (Supabase RLS off, API keys in bundles, IDOR, unauthed APIs).
Ran it against 1,764 apps across Lovable, Bolt, Replit, Vercel, and
others.

Results: 453 criticals. 7% of Lovable/Bolt apps have wide-open
databases. 15% of Bolt apps ship hardcoded API keys. 200 YC companies
scanned as control: 0%.

Interesting finding: Lovable had ZERO hardcoded-key findings — their
code generator routes API calls server-side by default. Bolt and v0
embed them client-side. Same Supabase backend, very different security
outcomes based on template architecture.

Full data + methodology: https://securityscanner.dev/reports/2026-q2
Technical writeup: https://securityscanner.dev/blog/beyond-supabase-rls-five-other-crits

Scanner is at securityscanner.dev — one free scan, no signup needed
(there's a quick-scan box on the homepage).

Stefan
stefan@securityscanner.dev
```

### Send to:

| # | Name | Publication | Contact | Note |
|---|---|---|---|---|
| 20 | Simon Willison | simonwillison.net | Mastodon: @simon@simonwillison.net | He'll engage if the data is solid — most influential voice |
| 21 | Dan Ni | TLDR Newsletter | via tldr.tech | 1.6M subscribers — one-liner submission |
| 22 | Kale Davis | Hacker Newsletter | kale@hey.com | HN-style link curation |
| 23 | Adam Stacoviak | Changelog | via changelog.com | Episode pitch |
| 24 | Jeff Delaney | Fireship (YouTube) | via fireship.io | "100 seconds" format |
| 25 | Tyler McGinnis | Bytes newsletter | tyler@ui.dev | JS-specific: keys in bundles |
| 26 | Graham Cluley | Smashing Security | via site | Irony angle: AI tools leaking AI keys |
| 27 | David Mytton | Console.dev | david@console.dev | Tool review angle |
| 28 | Casey Newton | Platformer | casey@platformer.news | "Move fast and break security" |
| 29 | The New Stack | thenewstack.io | via contact | Developer-focused methodology |
| 30 | TNW (The Next Web) | thenextweb.com | via tips | Already covered Lovable crisis |

---

## Timing

- **Today/Tomorrow:** Send Pitch A to the 14 security/tech contacts — they'll run it fastest
- **Same day:** Send Pitch C to Simon Willison + TLDR + Hacker Newsletter — amplification
- **24h later:** Send Pitch B to business press — let the tech coverage establish credibility first
- **Follow up 48h later** on anyone who didn't reply — single nudge, no more

## Key assets to link

- Q2 Report: `https://securityscanner.dev/reports/2026-q2`
- Per-platform analysis: `https://securityscanner.dev/blog/lovable-vs-bolt-vs-replit-rls`
- Non-RLS findings: `https://securityscanner.dev/blog/beyond-supabase-rls-five-other-crits`
- Lovable top 5 RLS: `https://securityscanner.dev/blog/top-5-supabase-rls-mistakes-on-lovable-apps`
- Scanner (try it): `https://securityscanner.dev`

# HN launch content pack

Copy-paste ready. Submit Tuesday 2026-04-21, 8:30am ET.

---

## 1. Hacker News submission

**Title:**
```
Show HN: We scanned 150 vibe-coded apps — here's what's leaking
```

**URL:**
```
https://securityscanner.dev/blog/top-5-supabase-rls-mistakes-on-lovable-apps
```

**Tags:** (no tags field; title handles it)

---

## 2. First-comment from @slederer (post within 60 seconds)

```
Hi HN — I built this after getting tired of finding the same RLS misconfig in every Supabase/Lovable app I touched. The scanner looks at any deployed URL and writes a SECURITY-FIX.md that Claude Code / Cursor / Cline can execute.

The 150-target batch in the post ran over two days. We found 22 CRITs across 6 apps: Supabase RLS off on real user data, subdomain takeovers (Vercel + Unbounce CNAMEs), a Replit app shipping an Anthropic + OpenAI + Google API key trio in the same public JS bundle. Each class is a separate blog post on the site.

All 150 targets were public. Scanner is read-only — GET + tiny POST payloads, no data exfiltrated beyond 200-byte response previews to confirm exposure. We sent disclosures (via the people.search endpoint, not platform routing) to every affected app before posting.

Happy to answer anything about the scanner architecture (FastAPI + SQLite + 40+ modules, source is in a private repo but I can walk through the design), the findings, or the disclosure process. One free scan, no card.
```

---

## 3. Twitter / X thread (cross-post at same minute)

**Tweet 1/6:**
```
Spent the last two weeks scanning 150 apps built with Lovable, Replit, Bolt, v0, and Cursor.

22 had a CRITICAL vulnerability.

Here's the pattern 🧵
```

**Tweet 2/6:**
```
By far the #1 issue: Supabase Row Level Security disabled on tables that hold real user data.

Example: a booking app had 11 tables readable by anyone with the public anon key — including client emails, account passwords, booking requests with customer phone numbers.
```

**Tweet 3/6:**
```
Why so common? Supabase ships tables with RLS OFF by default. Devs enable it once on the `profiles` table from the tutorial, then forget every table they add after.

In our batch: 14% of Lovable/Bolt apps had at least one table wide open.
```

**Tweet 4/6:**
```
Second pattern: AI provider keys in the client bundle.

We found a Replit app shipping a live `sk-ant-api03-...` Anthropic key + `sk-proj-...` OpenAI key + 2 Google API keys. All in `/assets/index-*.js`. Running real costs against the owner's account.

Rotate. Move calls server-side. Every time.
```

**Tweet 5/6:**
```
Third: subdomain takeovers.

Two real YC companies in the batch had dangling CNAMEs pointing at deleted Vercel + Unbounce pages. Anyone can reclaim those pages and serve content from their subdomain.

Five minutes to fix. Hours before an attacker phishes your customers otherwise.
```

**Tweet 6/6:**
```
Full writeup (7 findings categories + exact SQL fixes):
https://securityscanner.dev/blog/top-5-supabase-rls-mistakes-on-lovable-apps

Scanner itself is at https://securityscanner.dev — free first scan, works with Claude Code / Cursor / Cline via MCP.
```

---

## 4. Pre-launch friend-ping (send Monday night)

Channels: DM to 3-5 HN-active friends. Text:

```
Hey — going to post Security Scanner on HN tomorrow morning (Tue Apr 21, ~8:30am ET / 14:30 CET).

Post URL: https://news.ycombinator.com/item?id=<I'll share once live>

Two things if you have 2 min:
1. Upvote once you see the post
2. Leave ONE substantive comment (question about the findings, your own experience with vibe-coded apps, etc.) — real engagement ranks way more than upvotes

No pressure if bandwidth is tight. I'll share the link in this thread ~15 min before posting.
```

---

## 5. During-launch watch commands

Open 4 terminal tabs before posting:

**Tab 1 — scanner log tail:**
```bash
ssh -i ~/.ssh/secscan-key.pem ec2-user@44.195.165.192 tail -f /home/ec2-user/scanner.log
```

**Tab 2 — signup/scan counter (refresh every 60s):**
```bash
while true; do
  ssh -i ~/.ssh/secscan-key.pem ec2-user@44.195.165.192 "python3 -c '
import sqlite3
c = sqlite3.connect(\"/home/ec2-user/scanner.db\")
s = c.execute(\"SELECT COUNT(*) FROM users WHERE created_at > datetime(\\\"now\\\",\\\"-1 hour\\\")\").fetchone()[0]
r = c.execute(\"SELECT COUNT(*) FROM scan_runs WHERE started_at > datetime(\\\"now\\\",\\\"-1 hour\\\")\").fetchone()[0]
rt = c.execute(\"SELECT COUNT(*) FROM scan_runs WHERE status=\\\"running\\\"\").fetchone()[0]
print(f\"signups_1h={s}  scans_1h={r}  scans_running={rt}\")
'"
  sleep 60
done
```

**Tab 3 — HN post:** keep `https://news.ycombinator.com/item?id=<your-id>` open. Reply to every comment within 10 min during the first 2 hours.

**Tab 4 — Anthropic usage dashboard:** https://console.anthropic.com/settings/usage. If daily cost crosses $200, SSH in and `export ANTHROPIC_API_KEY=` (empty) in the scanner process env via `kill + restart` to halt AI-module burn. Deterministic modules continue running.

---

## 6. Kill-switch (if things go sideways)

If HN traffic triggers an outage OR cost spike:

**Reduce load:**
```bash
# Lower concurrency cap on the fly
ssh ec2 "sudo kill -9 \$(sudo lsof -ti:80); sleep 1; sudo bash -c 'set -a; source /home/ec2-user/scanner.env; set +a; export PORT=80 SCAN_CONCURRENCY_CAP=4; nohup python3 /home/ec2-user/scanner_app.py </dev/null >/home/ec2-user/scanner.log 2>&1 &'"
```

**Disable AI modules:**
```bash
# Restart with empty Anthropic key → all AI modules become no-ops
ssh ec2 "sudo kill -9 \$(sudo lsof -ti:80); sleep 1; sudo bash -c 'set -a; source /home/ec2-user/scanner.env; set +a; unset ANTHROPIC_API_KEY OPENAI_API_KEY; export PORT=80; nohup python3 /home/ec2-user/scanner_app.py </dev/null >/home/ec2-user/scanner.log 2>&1 &'"
```

**Put the whole scanner in maintenance mode:**
```bash
# Return 503 from Cloudflare Worker — quickest shield
# (To be set up ahead of time in CF → Workers → new route)
```

---

## 7. Post-launch 24-hour checklist

After the HN post dies (usually ~24 hrs):

- [ ] Screenshot the HN post at peak (for future marketing)
- [ ] Export `users` table where `created_at > post_time` — this is the launch cohort
- [ ] Email the launch cohort 2-3 days later: "how was your first scan? any issues?"
- [ ] Review the `findings` table for any especially-interesting CRITs from launch users → potential follow-up blog post
- [ ] Check Anthropic + OpenAI actual burn; compare to pre-launch baseline
- [ ] Revert EC2 from t3.2xlarge → t3.xlarge if no sustained load
- [ ] Write a "what we learned launching on HN" retrospective post → next blog entry

# Security Scanner Research Briefing

**Prepared for:** Brian Krebs
**From:** Stefan, securityscanner.dev
**Date:** April 2026

---

## Overview

We scanned 1,764 deployed web apps built with AI coding tools (Lovable, Bolt, Replit, Cursor, v0) and found 453 critical vulnerabilities across 53,000+ total findings. As a control, we scanned 200 Y Combinator companies — 0% had critical findings.

Every finding below was verified reproducible. Every affected app owner was privately disclosed to before this briefing.

Full methodology + aggregate data: https://securityscanner.dev/reports/2026-q2

---

## 10 Cases — Real People, Real Data Exposed

### 1. Therapist's coaching site — payment methods + therapy session notes

**Target:** ruth-prissman-coach.lovable.app (built with Lovable)
**Tables exposed:** 15, including `payment_methods`, `future_sessions`, `content_subscribers`, `email_delivery_attempts`, `story_subscribers`
**What's at risk:** Paying therapy clients' payment information, upcoming session schedules, email delivery logs, and subscriber lists. The site belongs to an Israeli therapist offering coaching sessions.
**How:** Supabase Row Level Security disabled on all 15 tables. The public "anon" API key (shipped in the JavaScript bundle) grants SELECT access to every row.
**Disclosure:** Owner emailed directly. No response at time of writing.

---

### 2. Booking platform — 43 tables including customer chat logs and uploaded files

**Target:** daily-booking-platform.lovable.app (built with Lovable)
**Tables exposed:** 43 — the largest single exposure we found. Includes `customers`, `booking_requests`, `chat_messages`, `chat_channels`, `chat_participants`, `customer_files_new`, `subscriptions`
**What's at risk:** An entire business platform's data: every customer record, every booking request, every chat message between staff and customers, and uploaded customer files.
**How:** Same pattern — Supabase RLS disabled. Anon key in the JS bundle.
**Disclosure:** Email to info@smartbookly.com bounced. Speculative addresses (hello@, support@, contact@) attempted.

---

### 3. CRM with leads, bookings, and payment records

**Target:** limitless-crm-app-se-hu4t.bolt.host (built with Bolt)
**Tables exposed:** 17, including `leads`, `bookings`, `upfront_payments`, `activities`, `availability`, `blocked_dates`, `businesses`, `crm_config`
**What's at risk:** A sales team's full pipeline: lead contact details, booking history, upfront payment amounts, business configurations. Enough to reconstruct who's paying what, and when.
**How:** Supabase RLS disabled. Auto-generated Bolt hostname suggests a prototype that went into production use.
**Disclosure:** Anonymous Bolt deploy — no owner contact found.

---

### 4. Agency dashboard — client accounts, emails, and social media credentials

**Target:** bearloom-dash.lovable.app (built with Lovable)
**Tables exposed:** 18, including `client_accounts`, `client_emails`, `client_social_accounts`, `client_growth_history`, `client_highlights`, `clients`
**What's at risk:** A marketing/growth agency's entire client roster: their email addresses, linked social media accounts, growth metrics, and account details. An attacker could use the social account data to impersonate or hijack client accounts.
**How:** Supabase RLS disabled on all tables.
**Disclosure:** Reported to Lovable platform.

---

### 5. Health booking app — IDOR leaks patient data by incrementing a number

**Target:** roti-mami-booking.replit.app (built with Replit)
**Vulnerability:** Insecure Direct Object Reference (IDOR) on `/api/bookings/{id}`
**What's at risk:** Any visitor can request `GET /api/bookings/1`, then `/api/bookings/2`, `/api/bookings/3`... Each response returns a different customer's name, phone number, email address, and appointment details. No authentication check.
**Why it matters:** IDOR is the #1 exploited vulnerability class in HackerOne's annual reports. This one requires zero tools — just a browser URL bar.
**How it happened:** AI code generators create CRUD endpoints with sequential IDs and no authorization middleware by default. The developer tested with their own data and never checked "what if I request someone else's ID."
**Disclosure:** Owner emailed at hello@rotimami.com.

---

### 6. Health records marketplace — IDOR on privacy-health endpoint

**Target:** data-trade-marketplace-1-russellmxavier.replit.app (built with Replit)
**Vulnerability:** IDOR on `/api/privacy-health/{id}`
**What's at risk:** Health-related records accessible by iterating numeric IDs. The endpoint name itself — "privacy-health" — indicates the data was intended to be private.
**Disclosure:** Developer (Russell Xavier, identifiable from hostname) emailed at russell.muti@gmail.com.

---

### 7. Replit app shipping Anthropic + OpenAI keys in the same JS bundle

**Target:** flow-analytics.replit.app (built with Replit)
**Keys exposed:** Both an Anthropic API key (`sk-ant-api03-...`) and an OpenAI project key (`sk-proj-...`) embedded in `/assets/index-Bcsl4CB1.js`
**What's at risk:** Direct financial harm. Anyone who extracts the keys can make API calls billed to the owner's account. A GPT-4 loop running on a stolen key can burn hundreds of dollars per hour. The Anthropic key gives access to Claude API calls on the same account.
**Additionally:** Two Google API keys were also found in the same bundle.
**Disclosure:** Reported via OpenAI's security program. OpenAI responded.

---

### 8. YC-backed coding startup with /.env and /.git/config publicly served

**Target:** syntropy.io (YC-backed)
**Vulnerability:** `/.env` and `/.git/config` both return HTTP 200 at the production URL
**What's at risk:** The `.env` file contains all production secrets (API keys, database credentials, session secrets). The `.git/config` allows an attacker to reconstruct the entire repository history using tools like `git-dumper` — including secrets that were committed and later "deleted" through force-push. Those secrets are still in the git object store.
**Why it matters:** This is a coding IDE startup — their own production environment has the vulnerability their users should be scanning for.
**Disclosure:** Emailed founders@syntropy.io.

---

### 9. College student management system — student records exposed

**Target:** acadflow-pvppcoe.vercel.app (built with Vercel/v0)
**Tables exposed:** 4 — `batch_students`, `profiles`, `subjects`, `support_tickets`
**What's at risk:** Student enrollment data, profile information, and support ticket contents for what appears to be a real Indian engineering college (PVPPCOE — Padmabhushan Vasantdada Patil Pratishthan's College of Engineering).
**Regulatory context:** Student data is protected under India's Digital Personal Data Protection Act, 2023.
**Disclosure:** Emailed principal@pvppcoe.ac.in and info.tech@pvppcoe.edu.

---

### 10. Cannabis company HR system — employee PII at a regulated business

**Target:** harvesthub.bolt.host (built with Bolt)
**Tables exposed:** 4 — `employee_profiles`, `employee_team_assignments`, `org_settings`, `user_profiles`
**What's at risk:** Staff PII (names, roles, team assignments) at Robust Premium Cannabis, a licensed Missouri dispensary. Cannabis is a heavily regulated industry where employee data carries additional compliance requirements.
**How:** Built by a third-party developer ("Efficiensee") using Bolt, deployed to bolt.host with Supabase RLS disabled.
**Disclosure:** Emailed info@robustmo.com with note to forward to the developer.

---

## The Pattern

Every case above was built by someone using an AI coding tool — Lovable, Bolt, or Replit — to ship a production app. The tools generated working code. The code works. The databases work. The APIs work. What's missing: the AI never added Row Level Security, never checked for IDOR, never moved API keys server-side. It optimized for "does it function?" and shipped the answer to "is it safe?" as the developer's problem.

The developer, in most cases, is a non-technical founder or a solo builder who chose these tools specifically because they don't know how to code. They trusted the tool. The tool didn't earn it.

## Aggregate Numbers

| Metric | Value |
|---|---|
| Apps scanned | 1,764 |
| Critical findings | 453 |
| Total findings | 53,126 |
| Lovable CRIT rate | 7.1% |
| Bolt CRIT rate | 7.3% |
| Replit CRIT rate | 2.1% |
| YC companies (control) | 0% |
| Bolt apps with hardcoded API keys | 15% |
| Disclosures sent | 35+ |

## Links

- Full Q2 report: https://securityscanner.dev/reports/2026-q2
- Per-platform breakdown: https://securityscanner.dev/blog/lovable-vs-bolt-vs-replit-rls
- Beyond RLS findings: https://securityscanner.dev/blog/beyond-supabase-rls-five-other-crits
- Scanner (try it): https://securityscanner.dev

## Contact

Stefan Lederer
stefan@securityscanner.dev
Signal: available on request

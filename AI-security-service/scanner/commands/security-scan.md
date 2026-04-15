---
name: security-scan
description: Scan this project's deployment for security vulnerabilities, analyze findings with AI, and implement fixes. Requires the security-scanner MCP to be configured.
---

# /security-scan

Scan the current project's deployed application for vulnerabilities, get Claude-powered analysis, and apply fixes directly.

## Step 1 — Detect the deployment URL

Search the project for the deployment URL in this order:
1. Read `CLAUDE.md` if present — look for IP addresses, URLs, hostnames, "deployed at", "live at"
2. Check `.env`, `.env.example`, `.env.local` for vars like `DEPLOY_URL`, `APP_URL`, `BASE_URL`, `HOST`, `SERVER_URL`, `PUBLIC_URL`
3. Check deploy scripts (`deploy.sh`, `Makefile`, `package.json` scripts) for target hosts
4. Check infrastructure configs (Terraform `outputs.tf`, CDK `outputs`, Docker Compose `ports`, Dockerfile `EXPOSE`)
5. Check CI configs (`.github/workflows/*`, `fly.toml`, `vercel.json`, `netlify.toml`)
6. If nothing found, ask the user for the URL

## Step 2 — Trigger the scan

Use the `scan_target` MCP tool with the detected URL:
```
scan_target(url="https://example.com", label="project-name")
```

Tell the user: "Starting security scan of https://example.com — this takes 2-5 minutes."

## Step 3 — Poll for completion

Call `get_scan_status(run_id)` every 30 seconds until `status == "completed"`. Show progress updates:
- "Running nmap port scan..."
- "Checking TLS configuration..."
- "Testing rate limiting..."
- "Running nuclei templates..."

Don't re-call more than 30 times (15 minutes). If still running after that, tell the user something may be wrong.

## Step 4 — Get AI-powered analysis

Call `analyze_security(run_id)` to get Claude's analysis. This returns a Markdown document with:
- Executive summary and risk score
- Attack chains (how findings combine into real risks)
- Per-target tech stack detection
- Prioritized remediation plan with specific code changes

## Step 5 — Present findings to the user

Summarize for the user:
- Total findings by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Top 3 most urgent issues with one-sentence descriptions
- Show the executive summary from the AI analysis

## Step 6 — Implement fixes interactively

For each fix in the analysis (CRITICAL → HIGH → MEDIUM order):

1. Read the file(s) mentioned in the fix
2. Check if the proposed change applies to this codebase (file exists, framework matches)
3. Show the user: "About to fix: {FIX-N}: {title}. Change {file}: {brief description}"
4. If the user approves (or has autonomous mode), make the edit
5. Run the verification command from the fix if provided
6. Confirm it worked

## Step 7 — Verify end-to-end

After implementing fixes, ask the user: "Run another scan to verify fixes took effect?" If yes, repeat from Step 2. The scanner will auto-compare against the previous run and show what's fixed.

## Handling errors

- **No API key**: Tell the user to visit https://securityscanner.dev, sign up, generate an API key, and add it to their MCP config
- **Plan limit reached**: Show the upgrade URL from the error response
- **Scan timeout**: Tell the user the target may be unreachable or heavily firewalled

## Tone

Be concise. Lead with findings, not explanations. Use severity badges in output: 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🔵 LOW. When showing fix code, show the diff, not the full file.

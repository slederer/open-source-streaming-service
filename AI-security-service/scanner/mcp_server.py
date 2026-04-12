"""MCP server for Security Scanner — works in Claude Code, Claude Desktop, Cursor, Cline, Windsurf.

Configure in ~/.claude/settings.json:
{
  "mcpServers": {
    "security-scanner": {
      "command": "python3",
      "args": ["-m", "scanner.mcp_server"],
      "env": {
        "SECURITY_SCANNER_API_KEY": "sk-sec-..."
      }
    }
  }
}
"""

import asyncio
import os
import sys
from typing import Any

import httpx

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("mcp package not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

API_URL = os.environ.get("SECURITY_SCANNER_URL", "https://security.slederer.com")
API_KEY = os.environ.get("SECURITY_SCANNER_API_KEY", "")

if not API_KEY:
    print(
        "ERROR: SECURITY_SCANNER_API_KEY not set.\n"
        "Get your API key at https://security.slederer.com/dashboard/keys",
        file=sys.stderr,
    )
    sys.exit(1)

mcp = FastMCP(
    "security-scanner",
    instructions=(
        "Security scanning service for deployed web applications. "
        "Use scan_target() to scan a URL/IP for vulnerabilities (nmap, TLS, headers, "
        "exposed endpoints, rate limiting, nuclei templates). "
        "After scanning, use analyze_security() to get Claude-powered fix instructions "
        "with attack chain analysis, or get_fix_instructions() for a quick fix plan. "
        "Scans typically take 2-5 minutes — poll get_scan_status() until status='completed'."
    ),
)


async def _api(method: str, path: str, json_body: dict | None = None) -> Any:
    """Call the scanner API with the user's API key."""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.request(
            method, f"{API_URL}{path}", headers=headers, json=json_body
        )
        if resp.status_code == 401:
            return {"error": "Invalid API key. Generate a new one at " + API_URL + "/dashboard/keys"}
        if resp.status_code == 402:
            data = resp.json()
            return {"error": data.get("error", "Upgrade required"), "upgrade_url": data.get("upgrade_url")}
        try:
            return resp.json()
        except Exception:
            return {"raw": resp.text, "status": resp.status_code}


@mcp.tool()
async def scan_target(url: str, label: str = "") -> dict:
    """
    Start a security scan on a URL or IP. Returns a run_id — use get_scan_status()
    to check progress. Scans take 2-5 minutes.

    Args:
        url: URL, hostname, or IP address to scan (e.g. "https://myapp.com" or "1.2.3.4")
        label: Optional human-readable label for this target
    """
    return await _api("POST", "/v1/scan", {"host": url, "label": label or url})


@mcp.tool()
async def get_scan_status(run_id: str) -> dict:
    """
    Get the current status of a scan. Returns status ('running', 'completed', 'aborted')
    and the findings so far. When status='completed', all findings are available.

    Args:
        run_id: The run ID returned by scan_target()
    """
    return await _api("GET", f"/v1/scan/{run_id}")


@mcp.tool()
async def get_findings(run_id: str = "", target: str = "", severity: str = "") -> dict:
    """
    Get security findings from a scan, optionally filtered by severity.

    Args:
        run_id: Scan run ID (if omitted, uses latest scan)
        target: Optional target filter (IP or hostname)
        severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    """
    if not run_id:
        runs = await _api("GET", "/v1/runs")
        if isinstance(runs, list) and runs:
            run_id = runs[0]["id"]
        else:
            return {"error": "No scans found. Use scan_target() first."}
    data = await _api("GET", f"/v1/scan/{run_id}")
    if not isinstance(data, dict) or "findings" not in data:
        return data
    findings = data["findings"]
    if target:
        findings = [f for f in findings if f.get("target") == target]
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.upper()]
    return {"run_id": run_id, "count": len(findings), "findings": findings}


@mcp.tool()
async def get_fix_instructions(run_id: str, target: str = "") -> str:
    """
    Get Markdown fix instructions for scan findings, optimized for Claude Code execution.
    Includes YAML frontmatter with metadata and structured FIX-N blocks per issue.

    Args:
        run_id: Scan run ID
        target: Optional — restrict to a single target's findings
    """
    headers = {"Authorization": f"Bearer {API_KEY}"}
    params = {"target": target} if target else {}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(f"{API_URL}/v1/scan/{run_id}/fix", headers=headers, params=params)
        if resp.status_code == 200:
            return resp.text
        return f"Error {resp.status_code}: {resp.text}"


@mcp.tool()
async def analyze_security(run_id: str) -> str:
    """
    Get AI-powered security analysis with executive summary, attack chains,
    and prioritized remediation. Uses Claude Sonnet. Consumes 1 AI analysis credit.

    Args:
        run_id: Scan run ID (must be completed)
    """
    result = await _api("POST", f"/v1/scan/{run_id}/analyze")
    if isinstance(result, dict) and "content" in result:
        return result["content"]
    return str(result)


@mcp.tool()
async def list_targets() -> list:
    """List all security scan targets configured for your account."""
    result = await _api("GET", "/v1/targets")
    return result if isinstance(result, list) else [result]


@mcp.tool()
async def add_target(host: str, label: str = "") -> dict:
    """
    Add a new scan target to your account.

    Args:
        host: URL, hostname, or IP to add as a target
        label: Optional human-readable name
    """
    return await _api("POST", "/v1/targets", {"host": host, "label": label or host})


@mcp.tool()
async def list_scans(limit: int = 10) -> list:
    """List recent scan runs."""
    result = await _api("GET", "/v1/runs")
    if isinstance(result, list):
        return result[:limit]
    return [result]


def main():
    mcp.run()


if __name__ == "__main__":
    main()

"""Tests for MCP server — mocks HTTP layer, verifies tool behavior.

Skipped on Python <3.10 (MCP SDK requires 3.10+).
"""

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Skip the entire module if MCP can't be imported (e.g. Python 3.9)
try:
    import mcp  # noqa: F401
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not MCP_AVAILABLE or sys.version_info < (3, 10),
    reason="MCP SDK requires Python 3.10+",
)


@pytest.fixture
def mcp_env():
    """Set env vars so mcp_server can be imported."""
    with patch.dict(os.environ, {"SECURITY_SCANNER_API_KEY": "sk-sec-testkey123456", "SECURITY_SCANNER_URL": "https://test.example.com"}):
        # Force re-import to pick up env
        import importlib
        import sys
        # Remove cached module if present
        sys.modules.pop("scanner.mcp_server", None)
        mod = importlib.import_module("scanner.mcp_server")
        yield mod


class TestMcpTools:
    @pytest.mark.asyncio
    async def test_scan_target_calls_v1_scan(self, mcp_env):
        with patch("scanner.mcp_server._api", new=AsyncMock(return_value={"run_id": "abc123", "status": "started"})) as mock_api:
            result = await mcp_env.scan_target.fn(url="https://myapp.com", label="myapp")
            mock_api.assert_called_once_with("POST", "/v1/scan", {"host": "https://myapp.com", "label": "myapp"})
            assert result["run_id"] == "abc123"

    @pytest.mark.asyncio
    async def test_get_scan_status(self, mcp_env):
        with patch("scanner.mcp_server._api", new=AsyncMock(return_value={"status": "running"})) as mock_api:
            result = await mcp_env.get_scan_status.fn(run_id="abc123")
            mock_api.assert_called_once_with("GET", "/v1/scan/abc123")
            assert result["status"] == "running"

    @pytest.mark.asyncio
    async def test_get_findings_filters_by_severity(self, mcp_env):
        mock_data = {
            "run_id": "abc",
            "findings": [
                {"target": "10.0.0.1", "severity": "HIGH", "title": "f1"},
                {"target": "10.0.0.1", "severity": "LOW", "title": "f2"},
                {"target": "10.0.0.2", "severity": "HIGH", "title": "f3"},
            ]
        }
        with patch("scanner.mcp_server._api", new=AsyncMock(return_value=mock_data)):
            result = await mcp_env.get_findings.fn(run_id="abc", severity="HIGH")
            assert result["count"] == 2
            assert all(f["severity"] == "HIGH" for f in result["findings"])

    @pytest.mark.asyncio
    async def test_get_findings_filters_by_target(self, mcp_env):
        mock_data = {
            "findings": [
                {"target": "10.0.0.1", "severity": "HIGH", "title": "f1"},
                {"target": "10.0.0.2", "severity": "HIGH", "title": "f2"},
            ]
        }
        with patch("scanner.mcp_server._api", new=AsyncMock(return_value=mock_data)):
            result = await mcp_env.get_findings.fn(run_id="abc", target="10.0.0.1")
            assert result["count"] == 1
            assert result["findings"][0]["target"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_findings_uses_latest_scan_when_no_run_id(self, mcp_env):
        async def fake_api(method, path, body=None):
            if path == "/v1/runs":
                return [{"id": "latest-run", "status": "completed"}]
            if path == "/v1/scan/latest-run":
                return {"findings": []}
            return {}
        with patch("scanner.mcp_server._api", new=AsyncMock(side_effect=fake_api)):
            result = await mcp_env.get_findings.fn()
            assert result["run_id"] == "latest-run"

    @pytest.mark.asyncio
    async def test_list_targets(self, mcp_env):
        with patch("scanner.mcp_server._api", new=AsyncMock(return_value=[{"id": 1, "host": "a.com"}])):
            result = await mcp_env.list_targets.fn()
            assert len(result) == 1
            assert result[0]["host"] == "a.com"

    @pytest.mark.asyncio
    async def test_add_target(self, mcp_env):
        with patch("scanner.mcp_server._api", new=AsyncMock(return_value={"id": 5, "host": "new.com"})) as mock_api:
            result = await mcp_env.add_target.fn(host="new.com", label="test")
            mock_api.assert_called_once_with("POST", "/v1/targets", {"host": "new.com", "label": "test"})
            assert result["host"] == "new.com"

    @pytest.mark.asyncio
    async def test_list_scans_respects_limit(self, mcp_env):
        with patch("scanner.mcp_server._api", new=AsyncMock(return_value=[{"id": f"r{i}"} for i in range(20)])):
            result = await mcp_env.list_scans.fn(limit=5)
            assert len(result) == 5

    @pytest.mark.asyncio
    async def test_get_fix_instructions_returns_markdown(self, mcp_env):
        async def fake_client(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "# Fixes\n\n## FIX-1: ..."
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.get = AsyncMock(return_value=MagicMock(status_code=200, text="# Fix file"))
        with patch("scanner.mcp_server.httpx.AsyncClient", return_value=mock_client):
            result = await mcp_env.get_fix_instructions.fn(run_id="abc")
            assert "# Fix file" in result

    @pytest.mark.asyncio
    async def test_api_unauthorized_returns_error(self, mcp_env):
        mock_resp = MagicMock(status_code=401)
        mock_resp.json.return_value = {"error": "Unauthorized"}
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.request = AsyncMock(return_value=mock_resp)
        with patch("scanner.mcp_server.httpx.AsyncClient", return_value=mock_client):
            result = await mcp_env._api("GET", "/v1/targets")
            assert "error" in result
            assert "API key" in result["error"]

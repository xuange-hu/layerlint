"""MCP surface: the served names must match the manifest, with descriptions."""

from __future__ import annotations

import asyncio

import pytest

from layerlint import mcp_server


def test_served_tools_match_manifest_with_descriptions():
    """The names an agent calls must be the names the manifest promises, and
    FastMCP serves an empty description when the registered function has no
    docstring - an unidentified tool is an uncallable tool."""
    pytest.importorskip("mcp")
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    served = {t.name for t in tools}
    manifest = {t["name"] for t in mcp_server.tool_manifest()}
    assert served == manifest, f"only served: {served - manifest}; only manifest: {manifest - served}"
    for t in tools:
        assert (t.description or "").strip(), f"{t.name} has no description"


def test_manifest_matches_the_tools_constant():
    pytest.importorskip("mcp")
    assert {t["name"] for t in mcp_server.tool_manifest()} == {
        str(entry["name"]) if isinstance(entry, dict) else str(entry)
        for entry in mcp_server.TOOLS
    }


def test_demo_tool_writes_and_audits(tmp_path):
    """One call must produce a bad Dockerfile and a real report for it."""
    pytest.importorskip("mcp")
    out = mcp_server._demo_impl({"path": str(tmp_path / "demo")})
    assert "wrote" in out
    assert (tmp_path / "demo" / "Dockerfile").is_file()
    # the corpus is deliberately bad, so the report must contain findings
    assert "LYR" in out

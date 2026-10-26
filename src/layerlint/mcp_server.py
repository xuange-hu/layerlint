"""MCP server — four tools, lazily imported so the CLI stays dependency-free.

The `mcp` package lives in an optional extra. Importing it at module scope would
break `pip install layerlint` for everyone who only wants the CLI, which is the
exact bug this project's own test_packaging.py exists to prevent.
"""

from __future__ import annotations

from typing import Any

__all__ = ["build_server", "tool_manifest", "main"]

TOOLS: list[dict[str, Any]] = [
    {
        "name": "layerlint_scan",
        "description": (
            "Audit a Dockerfile for security, layer-waste and build-quality problems. "
            "Returns every finding with file:line evidence and a risk score."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the Dockerfile"},
                "min_severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Lowest severity to include (default: info)",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "layerlint_layers",
        "description": (
            "Print one row per build layer: what each instruction adds, removes or installs, "
            "and which deletions cannot actually shrink the image."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to the Dockerfile"}},
            "required": ["path"],
        },
    },
    {
        "name": "layerlint_explain",
        "description": "Explain why a rule exists and the minimal fix for it.",
        "inputSchema": {
            "type": "object",
            "properties": {"rule": {"type": "string", "description": "Rule id, e.g. LYR502"}},
            "required": ["rule"],
        },
    },
    {
        "name": "layerlint_rules",
        "description": "List every rule id with its severity and title.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def tool_manifest() -> list[dict[str, Any]]:
    return TOOLS


def _scan_impl(arguments: dict[str, Any]) -> str:
    from .analyze import analyze
    from .parse import parse_dockerfile
    from .render import render_report

    path = arguments["path"]
    df = parse_dockerfile(path)
    report = analyze(df)
    return render_report(report, min_severity=arguments.get("min_severity", "info"))


def _layers_impl(arguments: dict[str, Any]) -> str:
    from .layers import build_model, layer_table
    from .parse import parse_dockerfile
    from .render import render_layers

    path = arguments["path"]
    df = parse_dockerfile(path)
    return render_layers(layer_table(build_model(df)), path)


def _explain_impl(arguments: dict[str, Any]) -> str:
    from .render import render_explain

    return render_explain(arguments["rule"])


def _rules_impl(_arguments: dict[str, Any]) -> str:
    from .render import render_rules

    return render_rules()


_IMPL = {
    "layerlint_scan": _scan_impl,
    "layerlint_layers": _layers_impl,
    "layerlint_explain": _explain_impl,
    "layerlint_rules": _rules_impl,
}


def build_server():
    """Construct the MCP server. Imports `mcp` here, on purpose."""
    import mcp  # noqa: F401  (import check: the extra must be installed)
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("layerlint")

    for spec in TOOLS:
        name = spec["name"]

        def make(name: str = name):
            async def handler(**kwargs):  # noqa: ANN001 - MCP passes a dict of arguments
                try:
                    return _IMPL[name](kwargs)
                except FileNotFoundError as exc:
                    return f"error: {exc}"
                except Exception as exc:  # a tool must never take the server down
                    return f"error: {type(exc).__name__}: {exc}"

            return handler

        server.tool(name=name, description=spec["description"])(make())

    return server


def main() -> None:
    server = build_server()
    server.run()

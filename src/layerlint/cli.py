"""Command line interface — stdlib only.

That constraint is load bearing: `layerlint` is a console script, so anything it
imports at module scope must be an install dependency. Keeping the CLI on the
standard library means the first command a visitor runs cannot fail on a missing
optional extra.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path

from . import __version__
from .analyze import analyze
from .demo import write_demo
from .layers import build_model, layer_table
from .model import parse_severity
from .parse import parse_dockerfile
from .render import render_explain, render_layers, render_report, render_rules
from .rules import RULES
from .sarif import dumps as sarif_dumps

EPILOG = (
    "examples:\n"
    "  layerlint demo && layerlint scan ./demo\n"
    "  layerlint layers Dockerfile\n"
    "  layerlint scan . --fail-on high\n"
    "  layerlint scan . --sarif layerlint.sarif\n"
)


def force_utf8_stdio() -> None:
    """Make stdout/stderr UTF-8 before the first byte is printed.

    Windows consoles default to cp1252/cp936, which cannot encode characters
    this tool prints by design. Without this, the first command a new visitor
    runs dies with ``UnicodeEncodeError: 'charmap' codec can't encode ...`` --
    a failure no Linux or macOS machine can reproduce. Reconfiguring is a no-op
    where the streams are already UTF-8.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # e.g. a plain StringIO in a test host
            continue
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") == "utf8":
            continue
        with contextlib.suppress(ValueError, OSError):  # detached / closed stream
            reconfigure(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="layerlint",
        description="Layer-aware security and build-quality audit for Dockerfiles.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"layerlint {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit a Dockerfile or a directory")
    scan.add_argument("path", nargs="?", default=".", help="Dockerfile or directory (default: .)")
    scan.add_argument("--min-severity", default="info", help="lowest severity to report")
    scan.add_argument("--fail-on", default="", help="exit 1 when a finding at or above this severity exists")
    scan.add_argument("--json", action="store_true", help="machine-readable report")
    scan.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 ('-' for stdout)")
    scan.add_argument("--ignore-rule", action="append", default=[], metavar="ID", help="suppress a rule id")

    layers = sub.add_parser("layers", help="print the layer map of a Dockerfile")
    layers.add_argument("path", nargs="?", default="Dockerfile", help="Dockerfile (default: ./Dockerfile)")
    layers.add_argument("--json", action="store_true")

    rules = sub.add_parser("rules", help="list every rule with its severity")
    rules.add_argument("--group", default="", help="only this group")

    explain = sub.add_parser("explain", help="why a rule exists and how to fix it")
    explain.add_argument("rule", help="rule id, e.g. LYR502")

    demo = sub.add_parser("demo", help="write a deliberately bad Dockerfile and audit it")
    demo.add_argument("path", nargs="?", default="layerlint-demo", help="target directory (default: layerlint-demo)")
    demo.add_argument("--force", action="store_true", help="overwrite an existing Dockerfile")
    demo.add_argument("--no-scan", action="store_true", help="only write the file")
    return parser


def _resolve(path: str) -> Path:
    p = Path(path)
    if p.is_dir():
        candidate = p / "Dockerfile"
        if candidate.exists():
            return candidate
        for name in ("dockerfile", "Containerfile"):
            alt = p / name
            if alt.exists():
                return alt
        return p / "Dockerfile"
    return p


def _cmd_scan(args) -> int:
    target = _resolve(args.path)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2

    df = parse_dockerfile(str(target))
    report = analyze(df)
    if args.ignore_rule:
        blocked = {r.upper() for r in args.ignore_rule}
        report.findings = [f for f in report.findings if f.rule.id not in blocked]

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    if args.sarif:
        text = sarif_dumps(report, version=__version__, min_severity=args.min_severity)
        if args.sarif == "-":
            print(text)
        else:
            Path(args.sarif).write_text(text, encoding="utf-8")
    if not args.json and args.sarif != "-":
        print(render_report(report, min_severity=args.min_severity), end="")

    if args.fail_on:
        from .model import at_least

        keep = set(at_least(args.fail_on))
        if any(f.rule.severity in keep for f in report.findings):
            return 1
    return 0


def _cmd_layers(args) -> int:
    target = _resolve(args.path)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2
    df = parse_dockerfile(str(target))
    model = build_model(df)
    rows = layer_table(model)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        print(render_layers(rows, str(target)), end="")
    return 0


def _cmd_rules(args) -> int:
    if args.group:
        group = args.group.lower()
        ids = [rid for rid, rule in sorted(RULES.items()) if rule.group == group]
        if not ids:
            print(f"error: no rules in group {args.group!r}", file=sys.stderr)
            return 2
        for rid in ids:
            print(f"{rid}  {RULES[rid].severity:<8} {RULES[rid].title}")
        return 0
    print(render_rules(), end="")
    return 0


def _cmd_explain(args) -> int:
    print(render_explain(args.rule), end="")
    return 0 if args.rule.upper() in RULES else 2


def _cmd_demo(args) -> int:
    try:
        target = write_demo(args.path, force=args.force)
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {target}")
    if args.no_scan:
        return 0
    df = parse_dockerfile(str(target))
    report = analyze(df)
    print(render_report(report), end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    force_utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        severity = getattr(args, "min_severity", None)
        if severity:
            parse_severity(severity)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    handlers = {
        "scan": _cmd_scan,
        "layers": _cmd_layers,
        "rules": _cmd_rules,
        "explain": _cmd_explain,
        "demo": _cmd_demo,
    }
    return handlers[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

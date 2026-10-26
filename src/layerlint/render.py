"""Text rendering. Plain text first: this has to survive `head -40` in a CI log."""

from __future__ import annotations

from .model import SEVERITY_ORDER, Report
from .rules import GROUPS, RULES

_BAR = {
    "critical": "CRITICAL",
    "high": "HIGH    ",
    "medium": "MEDIUM  ",
    "low": "LOW     ",
    "info": "INFO    ",
}


def render_report(report: Report, min_severity: str = "info", color: bool = False) -> str:
    findings = report.filtered(min_severity)
    counts = report.counts()
    lines: list[str] = []
    lines.append("")
    lines.append(f"  layerlint  {report.path}")
    lines.append(
        f"  {report.summary.stages} stage(s) · {report.summary.layers} layer(s) · "
        f"{len(findings)} finding(s) · risk {report.risk}/100 → {report.grade}"
    )
    counts_text = "  ".join(f"{name} {counts[name]}" for name in reversed(SEVERITY_ORDER) if counts[name])
    if counts_text:
        lines.append(f"  {counts_text}")
    build = report.summary
    extra = []
    if build.runs_as_root:
        extra.append(f"runs as {build.final_user or 'root'}")
    else:
        extra.append(f"runs as {build.final_user}")
    if build.exposed_ports:
        extra.append("ports " + ",".join(build.exposed_ports))
    if build.packages:
        extra.append(f"{len(build.packages)} package(s)")
    if build.waste_bytes_note:
        extra.append(build.waste_bytes_note)
    if extra:
        lines.append("  " + " · ".join(extra))
    lines.append("")

    if not findings:
        lines.append("  no findings at or above this severity.")
        lines.append("")
        return "\n".join(lines)

    by_file: dict[int, list] = {}
    for f in findings:
        by_file.setdefault(f.line, []).append(f)

    lines.append("  findings")
    for line in sorted(by_file):
        for f in by_file[line]:
            lines.append(f"    {_BAR[f.rule.severity]} {f.rule.id}  {report.path}:{line}")
            lines.append(f"      {f.rule.title}")
            if f.detail:
                lines.append(f"      {f.detail}")
            if f.snippet:
                lines.append(f"      > {f.snippet}")
    lines.append("")
    lines.append("  every finding carries file:line — read the line before you trust or dismiss it.")
    lines.append("")
    return "\n".join(lines)


def render_rules() -> str:
    lines = ["", "  layerlint rules", ""]
    for group, blurb in GROUPS.items():
        rules = sorted((r for r in RULES.values() if r.group == group), key=lambda r: r.id)
        if not rules:
            continue
        lines.append(f"  {group} — {blurb}")
        for r in rules:
            lines.append(f"    {r.id}  {_BAR[r.severity].strip():<8}  {r.title}")
        lines.append("")
    return "\n".join(lines)


def render_explain(rule_id: str) -> str:
    rule = RULES.get(rule_id.upper())
    if rule is None:
        near = [rid for rid in RULES if rid.startswith(rule_id.upper()[:4])]
        hint = f" (did you mean {', '.join(sorted(near))}?)" if near else ""
        return f"  unknown rule {rule_id!r}{hint}\n"
    return "\n".join(
        [
            "",
            f"  {rule.id}  {rule.severity.upper()}  {rule.title}",
            f"  group: {rule.group}" + (f"   cwe: {rule.cwe}" if rule.cwe else ""),
            "",
            "  why",
            _wrap(rule.why),
            "",
            "  fix",
            _wrap(rule.fix),
            "",
        ]
    )


def _wrap(text: str, width: int = 78, indent: str = "    ") -> str:
    words = text.split()
    out: list[str] = []
    line = indent
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = indent + word
        else:
            line = f"{line} {word}" if line.strip() else indent + word
    if line.strip():
        out.append(line)
    return "\n".join(out)


def render_layers(rows: list[dict], path: str) -> str:
    lines = ["", f"  layer map  {path}", ""]
    lines.append(f"    {'stage':<6}{'layer':<7}{'line':<6}{'instruction':<12}detail")
    lines.append(f"    {'-' * 6}{'-' * 7}{'-' * 6}{'-' * 12}{'-' * 40}")
    for row in rows:
        label = f"{row['directive']}"
        detail = row["args"]
        if row["packages"]:
            detail += f"  [pkg: {', '.join(row['packages'][:6])}]"
        if row["adds"]:
            detail += f"  [adds: {', '.join(row['adds'][:4])}]"
        if row["removes"]:
            detail += f"  [rm: {', '.join(row['removes'][:4])}]"
        if row["wasted"]:
            detail += f"  ** still in an earlier layer: {', '.join(row['wasted'])}"
        lines.append(f"    {str(row['stage']):<6}L{row['layer']:<6}{row['line']:<6}{label:<12}{detail}")
    lines.append("")
    lines.append("  ** = the bytes are still in the image: deleting in a later layer only writes a whiteout.")
    lines.append("")
    return "\n".join(lines)

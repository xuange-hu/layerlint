"""Data model: severity ordering, rules, findings, and the report summary.

The shapes here are deliberately dumb: everything is a plain dataclass with a
``to_dict()``. A single `docker build` already has enough moving parts; the data
model should be the one thing you never have to think about.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}


def parse_severity(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in SEVERITY_RANK:
        raise ValueError(f"unknown severity {value!r}; expected one of {SEVERITY_ORDER}")
    return v


def at_least(threshold: str) -> list[str]:
    """All severities at or above ``threshold``."""
    return SEVERITY_ORDER[SEVERITY_RANK[parse_severity(threshold)] :]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    group: str
    why: str
    fix: str
    cwe: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK[self.severity]


@dataclass
class Finding:
    rule: Rule
    line: int
    snippet: str
    detail: str = ""
    stage: int = 0
    layer: int = 0

    def location(self) -> str:
        return f"{self.line}"

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity,
            "group": self.rule.group,
            "line": self.line,
            "stage": self.stage,
            "layer": self.layer,
            "snippet": self.snippet,
            "detail": self.detail,
            "cwe": self.rule.cwe,
            "why": self.rule.why,
            "fix": self.rule.fix,
        }


@dataclass
class BuildSummary:
    """What the image *is*, independent of any finding."""

    path: str = ""
    stages: int = 0
    layers: int = 0
    base_images: list[str] = field(default_factory=list)
    final_user: str = ""
    runs_as_root: bool = True
    exposed_ports: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    entrypoint: str = ""
    cmd: str = ""
    has_healthcheck: bool = False
    waste_bytes_note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    path: str
    findings: list[Finding]
    summary: BuildSummary
    rules_run: int = 0

    def filtered(self, min_severity: str = "info") -> list[Finding]:
        floor = SEVERITY_RANK[parse_severity(min_severity)]
        return [f for f in self.findings if f.rule.severity_rank >= floor]

    def counts(self) -> dict[str, int]:
        out = {name: 0 for name in SEVERITY_ORDER}
        for f in self.findings:
            out[f.rule.severity] += 1
        return out

    @property
    def risk(self) -> int:
        """0-100. Weighted count, capped, so one critical cannot hide forty lows."""
        weights = {"info": 0, "low": 2, "medium": 6, "high": 14, "critical": 30}
        raw = sum(weights[f.rule.severity] for f in self.findings)
        return min(100, raw)

    @property
    def grade(self) -> str:
        r = self.risk
        if r >= 80:
            return "CRITICAL RISK"
        if r >= 55:
            return "HIGH RISK"
        if r >= 30:
            return "MEDIUM RISK"
        if r >= 12:
            return "LOW RISK"
        return "CLEAN"

    def to_dict(self) -> dict:
        return {
            "tool": "layerlint",
            "path": self.path,
            "summary": {
                "risk": self.risk,
                "grade": self.grade,
                "counts": self.counts(),
                "rules_run": self.rules_run,
                "build": self.summary.to_dict(),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

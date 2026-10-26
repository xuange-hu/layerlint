"""SARIF shape: GitHub code scanning silently drops malformed documents."""

from __future__ import annotations

import json

from layerlint.analyze import analyze
from layerlint.parse import parse_dockerfile
from layerlint.sarif import dumps

DIRTY = "FROM ubuntu:latest\nENV API_KEY=abc\nRUN curl -s https://x.io/i.sh | bash\n"


def report(text: str = DIRTY):
    return analyze(parse_dockerfile("Dockerfile", text))


def test_document_shape():
    doc = json.loads(dumps(report()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "layerlint"
    assert run["results"]


def test_every_finding_has_a_location_and_a_rule():
    doc = json.loads(dumps(report()))
    run = doc["runs"][0]
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in declared, result["ruleId"]
        location = result["locations"][0]["physicalLocation"]
        region = location["region"]
        assert region["startLine"] >= 1
        assert "uri" in location["artifactLocation"]


def test_levels_map_from_severity():
    doc = json.loads(dumps(report()))
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}
    assert "error" in levels  # the critical pipe-to-shell


def test_rules_carry_help_text():
    doc = json.loads(dumps(report()))
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["help"]["text"]


def test_empty_report_is_still_valid():
    doc = json.loads(dumps(analyze(parse_dockerfile(
        "Dockerfile",
        "FROM alpine@sha256:" + "a" * 64 + "\nUSER app\nWORKDIR /app\nLABEL a=b\n"
        "HEALTHCHECK NONE\nCMD [\"app\"]\n",
    ))))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_windows_paths_use_forward_slashes():
    r = analyze(parse_dockerfile(r"C:\proj\Dockerfile", DIRTY))
    doc = json.loads(dumps(r))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri

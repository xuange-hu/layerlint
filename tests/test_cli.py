"""CLI behaviour: exit codes are the CI contract, so they get their own tests."""

from __future__ import annotations

import json

import pytest

from layerlint.cli import main

CLEAN = "FROM alpine@sha256:" + "a" * 64 + "\nUSER app\nWORKDIR /app\nLABEL a=b\nHEALTHCHECK NONE\nCMD [\"app\"]\n"
DIRTY = "FROM ubuntu:latest\nENV API_KEY=abc\nRUN curl -s https://x.io/i.sh | bash\n"


@pytest.fixture
def dockerfile(tmp_path):
    def _write(text: str, name: str = "Dockerfile") -> str:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    return _write


def test_scan_reports_and_returns_zero(dockerfile, capsys):
    path = dockerfile(DIRTY)
    assert main(["scan", path]) == 0
    out = capsys.readouterr().out
    assert "LYR301" in out and "risk" in out


def test_fail_on_critical_exits_one(dockerfile, capsys):
    path = dockerfile(DIRTY)
    assert main(["scan", path, "--fail-on", "critical"]) == 1


def test_fail_on_high_is_zero_for_a_medium_only_file(dockerfile, capsys):
    path = dockerfile("FROM alpine@sha256:" + "a" * 64 + "\nUSER app\nWORKDIR /app\nLABEL a=b\nHEALTHCHECK NONE\nENV A=1\n")
    assert main(["scan", path, "--fail-on", "high"]) == 0


def test_json_output_is_parseable(dockerfile, capsys):
    path = dockerfile(DIRTY)
    assert main(["scan", path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["risk"] > 0
    assert data["findings"]
    assert "line" in data["findings"][0]


def test_sarif_file_is_written_and_valid(dockerfile, tmp_path):
    path = dockerfile(DIRTY)
    out = tmp_path / "r.sarif"
    assert main(["scan", path, "--sarif", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]


def test_min_severity_filters(dockerfile, capsys):
    path = dockerfile(DIRTY)
    main(["scan", path, "--min-severity", "critical"])
    assert "LOW" not in capsys.readouterr().out


def test_bad_severity_is_rejected(dockerfile, capsys):
    path = dockerfile(CLEAN)
    assert main(["scan", path, "--min-severity", "apocalyptic"]) == 2
    assert "error" in capsys.readouterr().err


def test_missing_file_exits_two(capsys):
    assert main(["scan", "/nonexistent/Dockerfile"]) == 2


def test_ignore_rule_removes_the_finding(dockerfile, capsys):
    path = dockerfile(DIRTY)
    main(["scan", path, "--ignore-rule", "LYR301"])
    assert "LYR301" not in capsys.readouterr().out


def test_directory_argument_finds_the_dockerfile(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_text(DIRTY, encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == 0
    assert "LYR301" in capsys.readouterr().out


def test_layers_command(dockerfile, capsys):
    path = dockerfile("FROM alpine:3.19\nCOPY ./c /c\nRUN rm -rf /c\n")
    assert main(["layers", path]) == 0
    out = capsys.readouterr().out
    assert "layer map" in out
    assert "still in an earlier layer" in out


def test_layers_json(dockerfile, capsys):
    path = dockerfile("FROM alpine:3.19\nRUN true\n")
    assert main(["layers", path, "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["directive"] == "RUN"


def test_rules_lists_every_rule(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "LYR101" in out and "LYR502" in out


def test_rules_group_filter(capsys):
    assert main(["rules", "--group", "secrets"]) == 0
    out = capsys.readouterr().out
    assert "LYR401" in out and "LYR101" not in out


def test_rules_unknown_group_exits_two(capsys):
    assert main(["rules", "--group", "nope"]) == 2


def test_explain_prints_why_and_fix(capsys):
    assert main(["explain", "LYR502"]) == 0
    out = capsys.readouterr().out
    assert "why" in out and "fix" in out


def test_explain_unknown_rule_exits_two(capsys):
    assert main(["explain", "NOPE"]) == 2


def test_demo_writes_then_audits(tmp_path, capsys):
    assert main(["demo", str(tmp_path / "demo")]) == 0
    out = capsys.readouterr().out
    assert (tmp_path / "demo" / "Dockerfile").exists()
    assert "risk" in out


def test_demo_refuses_to_clobber(tmp_path, capsys):
    target = tmp_path / "demo"
    target.mkdir()
    (target / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    assert main(["demo", str(target)]) == 2
    assert "error" in capsys.readouterr().err


def test_demo_force_overwrites(tmp_path):
    target = tmp_path / "demo"
    target.mkdir()
    (target / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    assert main(["demo", str(target), "--force", "--no-scan"]) == 0


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0

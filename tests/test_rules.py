"""One test per rule: the pattern that must fire, and the fix that must clear it.

Each test is written as "this Dockerfile line should be caught" rather than
"the analyser returns N", so a regression names itself.
"""

from __future__ import annotations

from layerlint.analyze import analyze
from layerlint.model import SEVERITY_RANK
from layerlint.parse import parse_dockerfile
from layerlint.rules import GROUPS, RULES, get


def scan(text: str, path: str = "Dockerfile"):
    df = parse_dockerfile(path, text)
    report = analyze(df)
    return {f.rule.id for f in report.findings}, report


def test_registry_is_well_formed():
    assert len(RULES) >= 30
    for rid, rule in RULES.items():
        assert rule.id == rid
        assert rule.severity in SEVERITY_RANK, rid
        assert rule.group in GROUPS, rid
        assert len(rule.why) > 60, f"{rid} why is too thin"
        assert len(rule.fix) > 20, f"{rid} fix is too thin"
        assert rule.cwe.startswith("CWE-"), rid
    assert get("LYR502").severity == "high"


# --------------------------------------------------------------------- base
def test_floating_base_tag():
    assert "LYR101" in scan("FROM ubuntu:latest\n")[0]
    assert "LYR101" in scan("FROM ubuntu\n")[0]


def test_digest_pinned_base_is_clean():
    assert "LYR101" not in scan("FROM ubuntu@sha256:" + "a" * 64 + "\n")[0]


def test_unnamed_stage_in_multi_stage():
    ids, _ = scan("FROM golang:1.22 AS builder\nFROM debian:12\n")
    assert "LYR102" in ids


def test_runtime_stage_without_user():
    ids, report = scan("FROM alpine:3.19 AS build\nUSER builder\nFROM alpine:3.19\nCMD [\"app\"]\n")
    assert "LYR103" in ids
    assert report.summary.runs_as_root is True


def test_user_in_runtime_stage_clears_it():
    ids, report = scan("FROM alpine:3.19\nUSER app\nCMD [\"app\"]\n")
    assert "LYR103" not in ids
    assert report.summary.runs_as_root is False


def test_explicit_root_user():
    assert "LYR104" in scan("FROM alpine:3.19\nUSER root\n")[0]


def test_sudo_in_run():
    assert "LYR105" in scan("FROM alpine:3.19\nRUN sudo apk add curl\n")[0]


def test_missing_healthcheck():
    assert "LYR106" in scan("FROM alpine:3.19\nCMD [\"app\"]\n")[0]


# ----------------------------------------------------------------- packages
def test_apt_update_and_install_split():
    ids, _ = scan("FROM debian:12\nRUN apt-get update\nRUN apt-get install -y curl\n")
    assert "LYR201" in ids


def test_apt_update_and_install_combined_is_clean():
    text = "FROM debian:12\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
    ids, _ = scan(text)
    assert "LYR201" not in ids


def test_no_install_recommends():
    assert "LYR202" in scan("FROM debian:12\nRUN apt-get install -y curl\n")[0]


def test_apt_cache_left_behind():
    assert "LYR203" in scan("FROM debian:12\nRUN apt-get update\n")[0]


def test_pip_cache_left_behind():
    assert "LYR203" in scan("FROM python:3.12\nRUN pip install requests\n")[0]


def test_apk_without_no_cache():
    assert "LYR203" in scan("FROM alpine:3.19\nRUN apk add curl\n")[0]


def test_unpinned_package_version():
    assert "LYR204" in scan("FROM python:3.12\nRUN pip install requests\n")[0]


def test_pinned_package_version_is_clean():
    ids, _ = scan("FROM python:3.12\nRUN pip install --no-cache-dir requests==2.32.3\n")
    assert "LYR204" not in ids


def test_npm_install_instead_of_ci():
    assert "LYR205" in scan("FROM node:22\nRUN npm install\n")[0]


def test_npm_ci_is_clean():
    assert "LYR205" not in scan("FROM node:22\nRUN npm ci\n")[0]


def test_insecure_package_flag():
    assert "LYR206" in scan("FROM alpine:3.19\nRUN apk add --allow-untrusted pkg\n")[0]


# ------------------------------------------------------------------ network
def test_pipe_to_shell():
    ids, report = scan("FROM alpine:3.19\nRUN curl -fsSL https://x.io/i.sh | bash\n")
    assert "LYR301" in ids
    assert report.risk >= 30


def test_download_then_execute():
    assert "LYR302" in scan("FROM alpine:3.19\nRUN curl -o /tmp/t https://x.io/t && chmod +x /tmp/t && /tmp/t\n")[0]


def test_add_remote_url():
    assert "LYR303" in scan("FROM alpine:3.19\nADD https://x.io/a.tar.gz /tmp/a.tgz\n")[0]


def test_add_local_archive():
    assert "LYR304" in scan("FROM alpine:3.19\nADD ./vendor.tar.gz /vendor\n")[0]


def test_cleartext_fetch():
    assert "LYR305" in scan("FROM alpine:3.19\nADD http://x.io/a.tar.gz /tmp/a.tgz\n")[0]


# ------------------------------------------------------------------ secrets
def test_secret_named_env():
    assert "LYR401" in scan("FROM alpine:3.19\nENV API_KEY=abc123\n")[0]


def test_secret_shaped_value():
    assert "LYR402" in scan("FROM alpine:3.19\nENV TOKEN=AKIAIOSFODNN7EXAMPLE\n")[0]


def test_secret_file_copied():
    assert "LYR403" in scan("FROM alpine:3.19\nCOPY .env /app/.env\n")[0]


def test_secret_written_by_run():
    assert "LYR404" in scan("FROM alpine:3.19\nRUN echo k=v > /app/credentials\n")[0]


def test_copy_all_without_dockerignore():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "Dockerfile"
        target.write_text("FROM alpine:3.19\nCOPY . /app\n", encoding="utf-8")
        ids, _ = scan(target.read_text(encoding="utf-8"), path=str(target))
        assert "LYR405" in ids


def test_copy_all_with_dockerignore_is_clean():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / ".dockerignore").write_text("*\n", encoding="utf-8")
        target = Path(tmp) / "Dockerfile"
        target.write_text("FROM alpine:3.19\nCOPY . /app\n", encoding="utf-8")
        ids, _ = scan(target.read_text(encoding="utf-8"), path=str(target))
        assert "LYR405" not in ids


# --------------------------------------------------------------- filesystem
def test_world_writable():
    assert "LYR501" in scan("FROM alpine:3.19\nRUN chmod -R 777 /app\n")[0]


def test_relative_workdir():
    assert "LYR503" in scan("FROM alpine:3.19\nWORKDIR app\n")[0]


def test_absolute_workdir_is_clean():
    assert "LYR503" not in scan("FROM alpine:3.19\nWORKDIR /app\n")[0]


# ------------------------------------------------------------------ runtime
def test_shell_form_cmd():
    assert "LYR601" in scan("FROM alpine:3.19\nCMD python3 -m http.server\n")[0]


def test_exec_form_cmd_is_clean():
    assert "LYR601" not in scan("FROM alpine:3.19\nCMD [\"python3\", \"-m\", \"http.server\"]\n")[0]


def test_duplicate_cmd():
    assert "LYR602" in scan("FROM alpine:3.19\nCMD a\nCMD b\n")[0]


def test_privileged_port_exposed():
    assert "LYR603" in scan("FROM alpine:3.19\nEXPOSE 22\n")[0]


def test_silenced_command():
    assert "LYR604" in scan("FROM alpine:3.19\nRUN apk add curl > /dev/null 2>&1\n")[0]


def test_missing_labels():
    assert "LYR605" in scan("FROM alpine:3.19\nCMD [\"app\"]\n")[0]

"""The demo is the product's first impression; it must never rot."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from layerlint.analyze import analyze
from layerlint.demo import DEMO_DOCKERFILE, write_demo
from layerlint.parse import parse_dockerfile
from layerlint.rules import RULES


@pytest.fixture(scope="module")
def demo_report(tmp_path_factory):
    directory = tmp_path_factory.mktemp("demo")
    path = write_demo(directory)
    return analyze(parse_dockerfile(str(path))), path


def test_demo_triggers_every_rule(demo_report):
    """If a rule stops firing, the demo stopped demonstrating it — fail loudly."""
    report, _ = demo_report
    fired = {f.rule.id for f in report.findings}
    missing = sorted(set(RULES) - fired)
    assert not missing, f"demo no longer triggers: {missing}"


def test_demo_is_reproducible_and_high_risk(demo_report):
    report, _ = demo_report
    assert report.risk == 100
    assert report.grade == "CRITICAL RISK"
    assert len(report.findings) >= len(RULES)


def test_demo_refuses_to_overwrite():
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "Dockerfile"
        write_demo(target)
        with pytest.raises(FileExistsError):
            write_demo(target)
        write_demo(target, force=True)


def test_demo_writes_a_directory_when_asked_for_one():
    with tempfile.TemporaryDirectory() as tmp:
        path = write_demo(Path(tmp) / "demo")
        assert path.name == "Dockerfile"
        assert path.read_text(encoding="utf-8") == DEMO_DOCKERFILE


def test_every_demo_line_is_a_real_instruction():
    df = parse_dockerfile("Dockerfile", DEMO_DOCKERFILE)
    assert {i.directive for i in df.instructions} >= {
        "FROM", "RUN", "COPY", "ADD", "ENV", "ARG", "USER", "WORKDIR", "EXPOSE",
        "CMD", "ENTRYPOINT",
    }

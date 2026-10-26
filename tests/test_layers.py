"""The layer model — the reason this tool exists instead of another rule list."""

from __future__ import annotations

from layerlint.analyze import analyze
from layerlint.layers import build_model, layer_table, orphaned_deletions
from layerlint.parse import parse_dockerfile


def model(text: str, path: str = "Dockerfile"):
    return build_model(parse_dockerfile(path, text))


def test_stages_are_numbered_and_aliased():
    m = model("FROM golang:1.22 AS builder\nFROM alpine:3.19 AS runtime\n")
    assert [s.number for s in m.stages] == [1, 2]
    assert [s.alias for s in m.stages] == ["builder", "runtime"]
    assert [s.base for s in m.stages] == ["golang:1.22", "alpine:3.19"]


def test_from_parent_reference_is_captured():
    m = model("FROM alpine:3.19\nCOPY --from=builder /out /in\n")
    layer = m.stages[0].layers[0]
    assert layer.instruction.flags["from"] == "builder"


def test_only_layer_making_directives_become_layers():
    m = model("FROM alpine:3.19\nLABEL a=b\nENV X=1\nRUN true\nCOPY . /app\nWORKDIR /app\n")
    assert [lay.directive for lay in m.stages[0].layers] == ["RUN", "COPY"]


def test_layer_index_is_per_stage():
    m = model("FROM a AS one\nRUN true\nRUN true\nFROM b AS two\nCOPY . /x\n")
    assert [lay.index for lay in m.stages[0].layers] == [1, 2]
    assert [lay.index for lay in m.stages[1].layers] == [1]


def test_copy_all_records_the_destination_tree():
    """`COPY . /app` must be recorded as /app, or a later rm -rf /app/x is unmatchable."""
    m = model("FROM alpine:3.19\nCOPY . /app\n")
    assert m.stages[0].layers[0].files_added == ["/app"]


def test_copy_named_file_records_source_and_destination():
    m = model("FROM alpine:3.19\nCOPY requirements.txt /app/requirements.txt\n")
    assert m.stages[0].layers[0].files_added == ["/app/requirements.txt"]


def test_run_removal_is_recorded():
    m = model("FROM alpine:3.19\nRUN rm -rf /var/cache && echo done\n")
    assert "/var/cache" in m.stages[0].layers[0].files_removed


def test_glob_removal_is_ignored():
    """`rm -rf /x/*` cannot be matched to a path, so claiming it would be a guess."""
    m = model("FROM alpine:3.19\nRUN rm -rf /var/cache/*\n")
    assert m.stages[0].layers[0].files_removed == []


def test_packages_are_extracted_from_run():
    m = model("FROM alpine:3.19\nRUN apk add --no-cache curl git\n")
    assert m.stages[0].layers[0].packages == ["curl", "git"]


def test_orphaned_deletion_is_detected_across_layers():
    m = model("FROM alpine:3.19\nCOPY ./secrets /app/secrets\nRUN rm -rf /app/secrets\n")
    hits = orphaned_deletions(m)
    assert len(hits) == 1
    removing, adding, path = hits[0]
    assert path == "/app/secrets"
    assert adding.index < removing.index


def test_deletion_in_the_same_run_is_not_orphaned():
    m = model("FROM alpine:3.19\nRUN apk add --no-cache curl && rm -rf /var/cache\n")
    assert orphaned_deletions(m) == []


def test_deletion_in_another_stage_is_not_reported():
    m = model(
        "FROM alpine:3.19 AS one\nCOPY ./x /x\n"
        "FROM alpine:3.19 AS two\nRUN rm -rf /x\n"
    )
    assert orphaned_deletions(m) == []


def test_orphaned_deletion_produces_a_finding_with_both_line_numbers():
    text = "FROM alpine:3.19\nCOPY ./secrets /app/secrets\nRUN rm -rf /app/secrets\n"
    report = analyze(parse_dockerfile("Dockerfile", text))
    hits = [f for f in report.findings if f.rule.id == "LYR502"]
    assert len(hits) == 1
    assert "line 2" in hits[0].detail and "L1" in hits[0].detail


def test_layer_table_marks_wasted_deletions():
    m = model("FROM alpine:3.19\nCOPY ./c /c\nRUN rm -rf /c\n")
    rows = layer_table(m)
    assert rows[1]["wasted"] == ["/c"]


def test_many_layers_triggers_the_layer_count_rule():
    body = "".join(f"RUN echo {i}\n" for i in range(18))
    report = analyze(parse_dockerfile("Dockerfile", "FROM alpine:3.19\n" + body))
    assert any(f.rule.id == "LYR606" for f in report.findings)


def test_dependencies_installed_after_copying_everything():
    text = (
        "FROM node:22\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        "RUN npm ci\n"
    )
    report = analyze(parse_dockerfile("Dockerfile", text))
    assert any(f.rule.id == "LYR504" for f in report.findings)


def test_manifest_before_sources_is_clean():
    text = (
        "FROM node:22\n"
        "WORKDIR /app\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm ci --omit=dev\n"
        "COPY . .\n"
    )
    report = analyze(parse_dockerfile("Dockerfile", text))
    assert "LYR504" not in {f.rule.id for f in report.findings}


def test_instructions_before_the_first_from_are_tolerated():
    m = model("LABEL stray=1\nFROM alpine:3.19\nRUN true\n")
    assert len(m.stages) == 1
    assert len(m.stages[0].layers) == 1

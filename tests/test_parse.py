"""Parser behaviour. Line numbers and continuations are the contract."""

from __future__ import annotations

from layerlint.parse import parse_dockerfile, shell_words, split_env_pairs


def parse(text: str, path: str = "Dockerfile"):
    return parse_dockerfile(path, text)


def test_comments_and_blank_lines_are_skipped():
    df = parse("# leading comment\n\nFROM alpine:3.19\n")
    assert [i.directive for i in df.instructions] == ["FROM"]


def test_line_numbers_survive_continuations():
    """A finding must point at the line a human reads as the instruction start."""
    df = parse("FROM alpine:3.19\nRUN apt-get update \\\n && apt-get install -y curl\n")
    run = df.of("RUN")[0]
    assert run.line == 2
    assert "apt-get install" in run.args
    assert run.args.count("apt-get") == 2


def test_continuation_with_a_comment_line_between():
    df = parse("RUN echo one \\\n# not a comment inside a continuation\n && echo two\n")
    run = df.of("RUN")[0]
    assert "echo one" in run.args and "echo two" in run.args


def test_inline_hash_is_not_a_comment():
    """In Docker, `#` only starts a comment at the beginning of a line."""
    df = parse("RUN echo 'a#b'\n")
    assert df.of("RUN")[0].args == "echo 'a#b'"


def test_copy_flags_are_parsed_out():
    df = parse("COPY --from=builder --chown=app:app /out/app /usr/bin/app\n")
    copy = df.of("COPY")[0]
    assert copy.flags == {"from": "builder", "chown": "app:app"}
    assert copy.args == "/out/app /usr/bin/app"


def test_flag_without_value_is_true():
    df = parse("COPY --link src dest\n")
    assert df.of("COPY")[0].flags == {"link": "true"}


def test_json_form_is_detected():
    df = parse('ENTRYPOINT ["/bin/app", "--flag"]\n')
    entry = df.of("ENTRYPOINT")[0]
    assert entry.json_form is True
    assert entry.args.startswith("[")


def test_shell_form_is_not_json():
    df = parse("ENTRYPOINT /bin/app --flag\n")
    assert df.of("ENTRYPOINT")[0].json_form is False


def test_unknown_directive_is_ignored_not_crashed():
    df = parse("FROM alpine:3.19\nFROBNICATE thing\nRUN true\n")
    assert {i.directive for i in df.instructions} == {"FROM", "RUN"}


def test_layer_making_directives():
    df = parse("FROM alpine:3.19\nLABEL a=b\nRUN true\nCOPY . /app\nENV X=1\n")
    assert [i.directive for i in df.instructions if i.is_layer()] == ["RUN", "COPY"]


def test_source_line_lookup():
    df = parse("FROM alpine:3.19\nRUN true\n")
    assert df.source_line(2) == "RUN true"
    assert df.source_line(99) == ""


def test_env_pairs_key_value_form():
    assert split_env_pairs("A=1 B=2") == [("A", "1"), ("B", "2")]


def test_env_pairs_with_quoted_value():
    assert split_env_pairs('MSG="hello world" N=3') == [("MSG", "hello world"), ("N", "3")]


def test_env_pairs_legacy_space_form():
    assert split_env_pairs("MY_VAR some value") == [("MY_VAR", "some value")]


def test_shell_words_respects_quotes():
    assert shell_words('a "b c" d') == ["a", '"b c"', "d"]

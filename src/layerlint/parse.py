"""Dockerfile parser — stdlib only, line numbers preserved.

Why not use an existing parser: every one of them either needs a dependency or
throws away the line number, and a security tool without `Dockerfile:23` is a
text generator. Line numbers are the whole product, so the parser keeps them.

Handled:
  * `#` comments (only a `#` at the start of a line is a comment in Docker)
  * backslash line continuations, including a trailing comment line inside one
  * `ENV`/`LABEL` in both `KEY=VALUE` and legacy `KEY VALUE` forms
  * `COPY`/`ADD` flags (`--from=`, `--chown=`, `--chmod=`, `--link`)
  * JSON (exec) form for RUN/CMD/ENTRYPOINT

Not handled (accepted, documented): the `escape` parser directive (`` ` ``), and
heredocs (`RUN <<EOF`). Both are rare; a heredoc body would be read as a plain
instruction, which degrades to "not understood" rather than a false positive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DIRECTIVES = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY",
    "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL",
    "HEALTHCHECK", "SHELL",
}

# Instructions that create a filesystem layer.
LAYER_MAKING = {"RUN", "COPY", "ADD"}


@dataclass
class Instruction:
    line: int                 # 1-based line of the directive
    directive: str            # upper-case
    args: str                 # everything after the directive, continuations joined
    flags: dict[str, str] = field(default_factory=dict)
    json_form: bool = False   # RUN/CMD/ENTRYPOINT given as a JSON array

    @property
    def raw(self) -> str:
        return f"{self.directive} {self.args}".strip()

    def words(self) -> list[str]:
        return self.args.split()

    def is_layer(self) -> bool:
        return self.directive in LAYER_MAKING


@dataclass
class Dockerfile:
    path: str
    instructions: list[Instruction]
    source: list[str] = field(default_factory=list)

    def of(self, directive: str) -> list[Instruction]:
        return [i for i in self.instructions if i.directive == directive]

    def source_line(self, number: int) -> str:
        if 1 <= number <= len(self.source):
            return self.source[number - 1]
        return ""


def parse_dockerfile(path: str, text: str | None = None) -> Dockerfile:
    if text is None:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    source = text.splitlines()
    instructions: list[Instruction] = []

    logical: list[tuple[int, str]] = []  # (start line, full logical line)
    buf = ""
    start = 0
    for idx, line in enumerate(source, start=1):
        stripped = line.strip()
        # Comment lines are removed before joining, including inside a
        # continuation: `RUN a \` / `# note` / `&& b` is one instruction.
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if not buf:
            start = idx
        if stripped.endswith("\\"):
            buf += stripped[:-1].rstrip() + " "
            continue
        buf += stripped
        logical.append((start, buf.strip()))
        buf = ""
    if buf.strip():
        logical.append((start, buf.strip()))

    for line_no, text_line in logical:
        head, _, rest = text_line.partition(" ")
        directive = head.strip().upper()
        args = rest.strip()
        if directive not in DIRECTIVES:
            continue  # unknown directive: ignore rather than invent a finding
        flags: dict[str, str] = {}
        if directive in ("COPY", "ADD"):
            while args.startswith("--"):
                token, _, args = args.partition(" ")
                key, eq, value = token[2:].partition("=")
                flags[key.lower()] = value if eq else "true"
                args = args.strip()
        json_form = directive in ("RUN", "CMD", "ENTRYPOINT") and args.startswith("[")
        instructions.append(
            Instruction(line=line_no, directive=directive, args=args, flags=flags, json_form=json_form)
        )

    return Dockerfile(path=path, instructions=instructions, source=source)


# --------------------------------------------------------------------------- #
# small helpers shared by the analyser
# --------------------------------------------------------------------------- #
def split_env_pairs(args: str) -> list[tuple[str, str]]:
    """`A=1 B="two words"` -> [("A","1"), ("B","two words")].

    The legacy space-separated form (`ENV KEY value`) is handled too, because
    plenty of Dockerfiles in the wild still use it and a secret in that form is
    still a secret.
    """
    pairs: list[tuple[str, str]] = []
    if args and "=" in args.split(" ", 1)[0]:
        key = ""
        value = ""
        quote = ""
        mode = "key"
        i = 0
        while i < len(args):
            ch = args[i]
            if quote:
                if ch == quote:
                    quote = ""       # closing delimiter is not part of the value
                else:
                    value += ch
                i += 1
                continue
            if ch in "\"'":
                quote = ch
                i += 1
                continue
            if mode == "key":
                if ch == "=":
                    mode = "value"
                else:
                    key += ch
            elif ch.isspace():
                if key:
                    pairs.append((key, value))
                key, value, mode = "", "", "key"
            else:
                value += ch
            i += 1
        if key:
            pairs.append((key, value))
        return pairs

    parts = args.split(None, 1)
    if len(parts) == 2:
        return [(parts[0], parts[1].strip().strip("\"'"))]
    return []


def unquote(value: str) -> str:
    return value.strip().strip("\"'")


def shell_words(value: str) -> list[str]:
    """Split a shell-ish string on whitespace, honouring quotes."""
    out: list[str] = []
    cur = ""
    quote = ""
    for ch in value:
        if quote:
            cur += ch
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            cur += ch
        elif ch.isspace():
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


JSON_ARRAY_RE = re.compile(r"^\s*\[(?P<body>.*)\]\s*$", re.DOTALL)


def json_form_args(args: str) -> list[str]:
    """`["a", "b"]` -> ["a", "b"]; [] on anything else."""
    m = JSON_ARRAY_RE.match(args or "")
    if not m:
        return []
    return [unquote(p) for p in m.group("body").split(",") if p.strip()]

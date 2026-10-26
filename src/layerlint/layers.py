"""The layer model — the part no other Dockerfile linter has.

hadolint and friends read a Dockerfile as a flat list of instructions. A build
is not flat: ``FROM`` opens a stage, and inside a stage each ``RUN``/``COPY``/
``ADD`` appends an immutable layer. That distinction is the difference between
saying "you used rm" and proving **the bytes are still in the image**:

    COPY ./secret-cache /tmp/cache      # layer 3: 400 MB
    RUN  rm -rf /tmp/cache              # layer 4: a whiteout, 0 bytes saved

Layer 3 is in the pushed image and `docker save` will hand it to anyone who
pulls. No line-local rule can see that; a layer model can. Everything in this
module is derived from the parse tree only — no daemon, no build, no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parse import Dockerfile, Instruction, shell_words, unquote


@dataclass
class Layer:
    """One immutable filesystem layer."""

    index: int            # 1-based inside the stage
    stage: int            # 1-based stage number
    instruction: Instruction
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)

    @property
    def line(self) -> int:
        return self.instruction.line

    @property
    def directive(self) -> str:
        return self.instruction.directive

    @property
    def creates_layer(self) -> bool:
        # ONBUILD and metadata directives do not add a layer of their own.
        return self.instruction.is_layer()


@dataclass
class Stage:
    number: int
    base: str = ""
    alias: str = ""
    parent: str = ""       # FROM x AS y --from=z
    layers: list[Layer] = field(default_factory=list)
    start_line: int = 0

    @property
    def name(self) -> str:
        return self.alias or f"stage-{self.number}"


@dataclass
class BuildModel:
    path: str
    stages: list[Stage]

    @property
    def layers(self) -> list[Layer]:
        return [layer for stage in self.stages for layer in stage.layers]

    @property
    def final_stage(self) -> Stage | None:
        return self.stages[-1] if self.stages else None


# --- what a COPY/ADD brings in ---------------------------------------------- #
def _copy_sources(instr: Instruction) -> list[str]:
    words = shell_words(instr.args)
    if len(words) < 2:
        return []
    # last word is the destination
    return list(words[:-1])


def _copy_destination(instr: Instruction) -> str:
    words = shell_words(instr.args)
    return words[-1] if words else ""


# --- what a RUN removes ----------------------------------------------------- #
RM_RE = re.compile(r"\brm\s+(?:-[a-zA-Z]*\s+)*(?P<paths>.+?)(?:\s*(?:&&|\|\||;|$))")
RMDIR_RE = re.compile(r"\brmdir\s+(?:-[a-zA-Z]*\s+)*(?P<paths>.+?)(?:\s*(?:&&|\|\||;|$))")


def _removed_paths(command: str) -> list[str]:
    paths: list[str] = []
    for regex in (RM_RE, RMDIR_RE):
        for m in regex.finditer(command):
            for token in shell_words(m.group("paths") or ""):
                token = unquote(token)
                if token.startswith("-") or any(ch in token for ch in "*?$"):
                    continue
                paths.append(token.rstrip("/"))
    return paths


# --- packages a RUN installs ------------------------------------------------ #
PKG_MANAGERS = {
    "apt-get": re.compile(r"\bapt-get\s+(?:-[a-z]+\s+)*install\b(?:.*?)(?=&&|\|\||;|$)"),
    "apt": re.compile(r"\bapt\s+(?:-[a-z]+\s+)*install\b(?:.*?)(?=&&|\|\||;|$)"),
    "apk": re.compile(r"\bapk\s+add\b(?:.*?)(?=&&|\|\||;|$)"),
    "yum": re.compile(r"\b(?:yum|dnf)\s+install\b(?:.*?)(?=&&|\|\||;|$)"),
    "pip": re.compile(r"\bpip[0-9.]*\s+install\b(?:.*?)(?=&&|\|\||;|$)"),
    "npm": re.compile(r"\bnpm\s+(?:install|i|ci)\b(?:.*?)(?=&&|\|\||;|$)"),
}


# Package-manager flags that consume the next token. `--no-cache` does not, so a
# blanket "skip what follows a dash" would silently drop the first real package.
VALUE_FLAGS = {
    "--trusted-host", "--index-url", "--extra-index-url", "--find-links",
    "-r", "--requirement", "-c", "--constraint", "-t", "--target",
    "--platform", "--python-version", "--only-binary",
}


def _installed_packages(command: str) -> list[str]:
    pkgs: list[str] = []
    for regex in PKG_MANAGERS.values():
        for m in regex.finditer(command or ""):
            skip_next = False
            for token in shell_words(m.group(0)):
                if skip_next:
                    skip_next = False  # the argument of a flag, not a package
                    continue
                if token in VALUE_FLAGS:
                    skip_next = True  # the argument belongs to the flag
                    continue
                if token.startswith("-"):
                    continue
                if token in {"install", "add", "i", "ci", "apt-get", "apt", "apk", "yum", "dnf"}:
                    continue
                if token.startswith(("npm", "pip")):
                    continue
                if any(ch in token for ch in (">", "/")):  # shell redirection or a path
                    continue
                pkgs.append(token)
    # de-duplicate, keep order
    seen: set[str] = set()
    return [p for p in pkgs if not (p in seen or seen.add(p))]


def build_model(df: Dockerfile) -> BuildModel:
    """Turn instructions into stages and layers."""
    model = BuildModel(path=df.path, stages=[])
    stage: Stage | None = None
    counter = 0

    for instr in df.instructions:
        if instr.directive == "FROM":
            counter += 1
            words = shell_words(instr.args)
            base = words[0] if words else ""
            alias = ""
            if len(words) >= 3 and words[1].upper() == "AS":
                alias = words[2]
            stage = Stage(
                number=counter,
                base=base,
                alias=alias,
                parent=instr.flags.get("from", ""),
                start_line=instr.line,
            )
            model.stages.append(stage)
            continue

        if stage is None:
            # Instructions before the first FROM are invalid Docker; ignore them
            # rather than crash — the parser's job is to describe, not validate.
            continue

        if not instr.is_layer():
            continue

        layer = Layer(index=len(stage.layers) + 1, stage=stage.number, instruction=instr)
        if instr.directive in ("COPY", "ADD"):
            dest = _copy_destination(instr)
            for src in _copy_sources(instr):
                src_u = unquote(src)
                if src_u in (".", "./", "*", "./*") or src_u.endswith("/."):
                    # `COPY . /app` brings in the whole destination tree; keeping the
                    # bare source would make later `rm -rf /app/x` unmatchable.
                    layer.files_added.append(dest if dest not in ("", ".") else "/")
                elif dest in ("", ".", "/"):
                    layer.files_added.append(src_u)
                elif dest.endswith("/"):
                    layer.files_added.append(f"{dest.rstrip('/')}/{src_u.split('/')[-1]}")
                else:
                    # A destination that is not a directory is the target path
                    # itself, whether it renames the file or keeps its name.
                    layer.files_added.append(dest)
        else:  # RUN
            command = "" if instr.json_form else instr.args
            layer.files_removed = _removed_paths(command)
            layer.packages = _installed_packages(command)
        stage.layers.append(layer)

    return model


def orphaned_deletions(model: BuildModel) -> list[tuple[Layer, Layer, str]]:
    """``(removing_layer, adding_layer, path)`` for every `rm` that cannot shrink.

    A `RUN rm` only removes bytes from its *own* layer. If the path was written
    by a previous layer of the same stage, the data stays in that earlier layer
    and travels with every push, pull and `docker save`.
    """
    hits: list[tuple[Layer, Layer, str]] = []
    for stage in model.stages:
        added: list[tuple[Layer, str]] = []
        for layer in stage.layers:
            for path in layer.files_added:
                if layer.directive in ("COPY", "ADD"):
                    added.append((layer, path))
        for layer in stage.layers:
            for removed in layer.files_removed:
                for src_layer, src_path in added:
                    if src_layer.index >= layer.index:
                        continue
                    if _same_path(src_path, removed):
                        hits.append((layer, src_layer, removed))
    return hits


def _same_path(a: str, b: str) -> bool:
    def norm(text: str) -> str:
        return "/" + text.strip().strip("\"'").strip("/")

    a_n, b_n = norm(a), norm(b)
    if a_n == b_n:
        return True
    return a_n.startswith(b_n + "/") or b_n.startswith(a_n + "/")


def layer_table(model: BuildModel) -> list[dict]:
    """A flat, printable view of the build: one row per layer."""
    rows: list[dict] = []
    orphans = {(r.index, p) for r, _, p in orphaned_deletions(model)}
    for stage in model.stages:
        for layer in stage.layers:
            rows.append(
                {
                    "stage": stage.number,
                    "stage_name": stage.name,
                    "layer": layer.index,
                    "line": layer.line,
                    "directive": layer.directive,
                    "args": layer.instruction.args[:70],
                    "adds": layer.files_added,
                    "removes": layer.files_removed,
                    "packages": layer.packages,
                    "wasted": [p for p in layer.files_removed if (layer.index, p) in orphans],
                }
            )
    return rows

"""The checks.

One rule id per concrete failure mode, every finding carrying
``Dockerfile:line`` plus the raw instruction. The layer-aware rules (LYR502,
LYR504, LYR606) read the build model from ``layers.py``; everything else is
line-local and cheap.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable

from .layers import VALUE_FLAGS, BuildModel, orphaned_deletions
from .model import BuildSummary, Finding, Report
from .parse import Dockerfile, Instruction, shell_words, split_env_pairs, unquote
from .rules import RULES

SECRET_NAME = re.compile(
    r"(?:^|_)(?:api[-_]?key|secret|token|passwd|password|credential|private[-_]?key|"
    r"access[-_]?key|auth|session[-_]?key|client[-_]?secret)(?:$|_)",
    re.IGNORECASE,
)
SECRET_VALUE = re.compile(
    r"AKIA[0-9A-Z]{16}"                    # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{20,}"         # GitHub token
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"       # Slack token
    r"|sk-[A-Za-z0-9]{20,}"                # OpenAI-style key
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."  # JWT
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)
SECRET_FILE = re.compile(
    r"(^|/)\.env(\..+)?$|id_[rd]sa$|\.pem$|\.key$|\.p12$|\.pfx$|\.npmrc$|"
    r"\.git-credentials$|\.htpasswd$|\.docker/config\.json$|(^|/)credentials?$|(^|/)secrets?\.",
    re.IGNORECASE,
)
ARCHIVE = re.compile(r"\.(tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|zip|gz|bz2|xz)$", re.IGNORECASE)
URL = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
PIPE_TO_SHELL = re.compile(r"(?:curl|wget)\b[^\n|]*\|[^\n]*(?:ba|z|fi|k|da)?sh\b|\|\s*(?:sudo\s+)?(?:ba|z|fi|k)?sh\b")
DOWNLOAD_TO_FILE = re.compile(r"(?:curl|wget)\b[^\n]*\s(?:-o|--output|-O)\s+(?P<path>[^\s&|;]+)")
EXEC_OF_DOWNLOAD = re.compile(r"(?:chmod\s+\+x|(?:/bin/|/usr/bin/)?(?:ba|z|da)?sh\s+|^\./)", re.MULTILINE)
INSECURE_FLAGS = re.compile(
    r"--allow-untrusted|--insecure|--no-check-certificate|--disable-gpg-check|"
    r"--trusted-host\s+\S+|--strict-ssl=false|--no-verify|-k\s+https://|GIT_SSL_NO_VERIFY"
)
WORLD_WRITABLE = re.compile(r"chmod\s+(?:-R\s+)?(?:a\+rwx|0?777|0?666|o\+w)")
SECRET_REDIRECT = re.compile(r">\s*\S*(?:credential|token|secret|passw|api[-_]?key|\.env)", re.IGNORECASE)
SILENCED = re.compile(r">\s*/dev/null\s+2>&1|2>&1\s*>\s*/dev/null|\|\|\s*true\s*$")
APT = re.compile(r"\bapt-get\s+install\b|\bapt\s+install\b")
APT_UPDATE = re.compile(r"\bapt-get\s+update\b")
PIP_INSTALL = re.compile(r"\bpip[0-9.]*\s+install\b")
NPM_INSTALL = re.compile(r"\bnpm\s+(?:install|i)\b")
NPM_CI = re.compile(r"\bnpm\s+ci\b")
APK_ADD = re.compile(r"\bapk\s+add\b")
DNF_INSTALL = re.compile(r"\b(?:yum|dnf)\s+install\b")
PRIV_PORT = re.compile(r"^\s*(\d+)(?:/(?:tcp|udp))?\s*$")

MANIFEST_NAMES = {"package.json", "package-lock.json", "requirements.txt", "Pipfile.lock",
                  "poetry.lock", "pyproject.toml", "go.mod", "go.sum", "Gemfile.lock",
                  "Cargo.toml", "Cargo.lock", "composer.json", "yarn.lock", "pnpm-lock.yaml"}


def analyze(df: Dockerfile, model: BuildModel | None = None) -> Report:
    if model is None:
        from .layers import build_model as _build

        model = _build(df)

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def emit(rule_id: str, line: int, detail: str = "", stage: int = 0, layer: int = 0) -> None:
        rule = RULES.get(rule_id)
        if rule is None or (rule_id, line) in seen:
            return
        seen.add((rule_id, line))
        findings.append(
            Finding(
                rule=rule,
                line=max(1, line),
                snippet=df.source_line(max(1, line)).strip()[:180] or "",
                detail=detail,
                stage=stage,
                layer=layer,
            )
        )

    for instr in df.instructions:
        _check_instruction(df, instr, emit)

    _check_layer_model(df, model, emit)
    _check_whole_build(df, emit)

    findings.sort(key=lambda f: (f.line, f.rule.id))
    return Report(
        path=df.path,
        findings=findings,
        summary=_summarise(df, model),
        rules_run=len(RULES),
    )


# --------------------------------------------------------------------------- #
# per-instruction checks
# --------------------------------------------------------------------------- #
def _check_instruction(df: Dockerfile, i: Instruction, emit: Callable[..., None]) -> None:
    args = i.args
    words = shell_words(args)
    lower = args.lower()

    if i.directive == "FROM":
        base = words[0] if words else ""
        if base and "@sha256:" not in base:
            # tag is the part after the last ':' that is not part of a registry host
            after_host = base.split("/")[-1]
            tag = after_host.rsplit(":", 1)[1] if ":" in after_host else ""
            if not tag or tag == "latest":
                emit("LYR101", i.line, f"'{base}' is not pinned to a digest.")
        if len(df.of("FROM")) > 1 and " as " not in lower:
            emit("LYR102", i.line, f"stage starting at '{base}' has no AS alias.")

    elif i.directive == "USER":
        value = unquote(args).lower()
        if value in ("root", "0", "toor") or value.startswith("root:"):
            emit("LYR104", i.line, f"switches to '{value}'.")

    elif i.directive == "WORKDIR":
        target = unquote(args)
        if not target.startswith("/") and not target.startswith("$"):
            emit("LYR503", i.line, f"WORKDIR '{target}' is not absolute.")

    elif i.directive == "EXPOSE":
        for port in args.split():
            m = PRIV_PORT.match(port)
            if m and int(m.group(1)) <= 1024:
                emit("LYR603", i.line, f"exposes privileged port {m.group(1)}.")

    elif i.directive == "ADD":
        for src in words[:-1] if len(words) > 1 else words:
            src_u = unquote(src)
            if URL.match(src_u):
                emit("LYR303", i.line, f"ADD downloads '{src_u}' at build time.")
                if src_u.lower().startswith("http://"):
                    emit("LYR305", i.line, f"'{src_u}' is fetched over cleartext http.")
            elif ARCHIVE.search(src_u):
                emit("LYR304", i.line, f"ADD auto-extracts '{src_u}'.")

    elif i.directive == "COPY":
        sources = words[:-1] if len(words) > 1 else []
        for src in sources:
            src_u = unquote(src)
            if SECRET_FILE.search(src_u) or src_u in (".env", ".git"):
                emit("LYR403", i.line, f"copies '{src_u}', which is credential material.")
        copies_everything = (
            len(words) >= 2
            and words[0] in (".", "./", "*")
            and words[1] in (".", "./", "/app", "/src", "/opt/app")
        )
        ignore_file = os.path.join(os.path.dirname(df.path) or ".", ".dockerignore")
        if copies_everything and not os.path.exists(ignore_file):
            emit("LYR405", i.line, "COPY of the whole tree with no .dockerignore next to the Dockerfile.")

    elif i.directive in ("ENV", "ARG"):
        for key, value in split_env_pairs(args):
            name = key.strip()
            if SECRET_NAME.search(name):
                emit("LYR401", i.line, f"'{name}' holds credential material by its name.")
            if SECRET_VALUE.search(value or ""):
                emit("LYR402", i.line, f"'{name}' is set to something that looks like a live credential.")

    elif i.directive == "RUN":
        command = "" if i.json_form else args
        _check_run(i, command, emit)

    elif i.directive in ("ENTRYPOINT", "CMD"):
        if not i.json_form:
            emit("LYR601", i.line, f"{i.directive} uses shell form, so PID 1 is a shell and SIGTERM is not forwarded.")


def _check_run(i: Instruction, command: str, emit: Callable[..., None]) -> None:
    if not command:
        return
    if PIPE_TO_SHELL.search(command):
        emit("LYR301", i.line, "remote content is piped straight into a shell.")
    if "http://" in command and re.search(r"\b(?:curl|wget)\b", command):
        emit("LYR305", i.line, "fetches over cleartext http://.")
    if INSECURE_FLAGS.search(command):
        emit("LYR206", i.line, "package manager verification is switched off.")
    if re.search(r"\bsudo\b|\bsu\s+-", command):
        emit("LYR105", i.line, "privilege escalation inside the build.")
    if WORLD_WRITABLE.search(command):
        emit("LYR501", i.line, "grants world-writable permissions.")
    if SILENCED.search(command):
        emit("LYR604", i.line, "failures are discarded.")
    if "apt-get" in command and "rm -rf /var/lib/apt/lists" not in command:
        emit("LYR203", i.line, "apt metadata stays in the layer.")
    if APT.search(command):
        if "--no-install-recommends" not in command:
            emit("LYR202", i.line, "apt-get install pulls in recommended packages.")
        for pkg in _apt_packages(command):
            if "=" not in pkg:
                emit("LYR204", i.line, f"'{pkg}' is installed without a version pin.")
                break
    if APK_ADD.search(command) and "--no-cache" not in command:
        emit("LYR203", i.line, "apk caches the index in the layer.")
    if PIP_INSTALL.search(command):
        if "--no-cache-dir" not in command:
            emit("LYR203", i.line, "pip writes its cache into the layer.")
        for pkg in _pip_packages(command):
            if "==" not in pkg and not pkg.startswith(("-", ".")) and "/" not in pkg:
                emit("LYR204", i.line, f"'{pkg}' is installed without a pinned version.")
                break
    if NPM_INSTALL.search(command) and not NPM_CI.search(command) and "--production" not in command:
        emit("LYR205", i.line, "npm install may rewrite the lockfile; npm ci does not.")
    if DNF_INSTALL.search(command) and "clean all" not in command:
        emit("LYR203", i.line, "dnf/yum metadata stays in the layer.")

    m = DOWNLOAD_TO_FILE.search(command)
    if m and EXEC_OF_DOWNLOAD.search(command):
        emit("LYR302", i.line, f"downloads '{m.group('path')}' and runs it without verifying it.")

    # credential written to disk: a redirect whose target *or* value looks secret
    if SECRET_REDIRECT.search(command) or SECRET_VALUE.search(command) and re.search(r">\s*\S+", command):
        emit("LYR404", i.line, "writes credential material into the layer.")


def _apt_packages(command: str) -> list[str]:
    out: list[str] = []
    for chunk in re.split(r"&&|\|\||;", command):
        if APT.search(chunk):
            for token in shell_words(chunk):
                if token.startswith("-") or token in {"apt-get", "apt", "install", "update", "yes", "-y"}:
                    continue
                out.append(token)
    return out


def _pip_packages(command: str) -> list[str]:
    out: list[str] = []
    skip = [False]
    for chunk in re.split(r"&&|\|\||;", command):
        if PIP_INSTALL.search(chunk):
            for token in shell_words(chunk):
                if token in VALUE_FLAGS:
                    skip[0] = True       # --trusted-host pypi.internal is not a package
                    continue
                if skip[0]:
                    skip[0] = False
                    continue
                if token.startswith("-") or token.startswith("pip") or token == "install":
                    continue
                if "." in token or any(ch in token for ch in (">", "/")):
                    continue
                out.append(token)
    return out


# --------------------------------------------------------------------------- #
# layer-aware checks
# --------------------------------------------------------------------------- #
def _check_layer_model(df: Dockerfile, model: BuildModel, emit: Callable[..., None]) -> None:
    for removing, adding, path in orphaned_deletions(model):
        emit(
            "LYR502",
            removing.line,
            f"'{path}' was written by layer L{adding.index} (line {adding.line}) and deleted "
            f"here — the bytes remain in L{adding.index} of this image.",
            stage=removing.stage,
            layer=removing.index,
        )

    for stage in model.stages:
        if len(stage.layers) > 15:
            emit("LYR606", stage.start_line, f"stage {stage.number} has {len(stage.layers)} layers.", stage=stage.number)

        copy_all_line = None
        install_line = None
        for layer in stage.layers:
            if layer.directive in ("COPY", "ADD") and any(
                unquote(s) in (".", "./") for s in shell_words(layer.instruction.args)[:-1]
            ):
                install_line = None
                copy_all_line = layer.line
            if layer.directive == "RUN" and any(
                pattern.search(layer.instruction.args)
                for pattern in (PIP_INSTALL, NPM_INSTALL, NPM_CI, APT, APK_ADD, DNF_INSTALL)
            ):
                install_line = layer.line
            if copy_all_line and install_line and install_line > copy_all_line:
                emit(
                    "LYR504",
                    install_line,
                    f"dependencies are installed after the whole tree was copied (line {copy_all_line}), "
                    "so every source edit busts the dependency layer.",
                    stage=stage.number,
                )
                copy_all_line = install_line = None

    # apt-get update split from apt-get install
    update_lines = [i.line for i in df.of("RUN") if APT_UPDATE.search(i.args)]
    install_lines = [i.line for i in df.of("RUN") if APT.search(i.args)]
    if update_lines and install_lines and not set(update_lines) & set(install_lines):
        emit("LYR201", min(install_lines), "apt-get update and apt-get install live in different layers.")


# --------------------------------------------------------------------------- #
# whole-build checks
# --------------------------------------------------------------------------- #
def _check_whole_build(df: Dockerfile, emit: Callable[..., None]) -> None:
    first = df.instructions[0].line if df.instructions else 1
    _check_final_user(df, emit)
    if not df.of("HEALTHCHECK"):
        emit("LYR106", first, "no HEALTHCHECK; an orchestrator cannot tell a wedged process from a healthy one.")
    if not df.of("LABEL"):
        emit("LYR605", first, "no labels, so the image carries no provenance.")
    if not df.of("WORKDIR"):
        emit("LYR503", first, "no WORKDIR; commands run wherever the base image left them.")

    for directive in ("CMD", "ENTRYPOINT"):
        hits = df.of(directive)
        if len(hits) > 1:
            for earlier in hits[:-1]:
                emit("LYR602", earlier.line, f"a later {directive} overrides this one.")


def _check_final_user(df: Dockerfile, emit: Callable[..., None]) -> None:
    """Whether the *runtime* stage drops privileges.

    Checking the whole file would be wrong: `USER builder` inside a compile
    stage says nothing about what ships. Only instructions after the last FROM
    describe the image that gets pushed, so that is what is examined here.
    """
    last_from = 0
    for instr in df.instructions:
        if instr.directive == "FROM":
            last_from = instr.line
    runtime_users = [i for i in df.of("USER") if i.line > last_from]
    if not runtime_users:
        target = df.source_line(last_from).strip() or f"line {last_from}"
        emit(
            "LYR103",
            max(1, last_from),
            f"the runtime stage ({target}) never sets USER, so the container runs as root.",
        )


def _summarise(df: Dockerfile, model: BuildModel) -> BuildSummary:
    last_from = max((i.line for i in df.of("FROM")), default=0)
    runtime_users = [i for i in df.of("USER") if i.line > last_from]
    final_user = unquote(runtime_users[-1].args) if runtime_users else "root"
    ports: list[str] = []
    for i in df.of("EXPOSE"):
        ports.extend(shell_words(i.args))
    packages: list[str] = []
    seen: set[str] = set()
    for layer in model.layers:
        for pkg in layer.packages:
            if pkg not in seen:
                seen.add(pkg)
                packages.append(pkg)
    entrypoint = df.of("ENTRYPOINT")[-1].args if df.of("ENTRYPOINT") else ""
    cmd = df.of("CMD")[-1].args if df.of("CMD") else ""
    orphan_count = len(orphaned_deletions(model))
    return BuildSummary(
        path=df.path,
        stages=len(model.stages),
        layers=len(model.layers),
        base_images=[s.base for s in model.stages if s.base],
        final_user=final_user,
        runs_as_root=final_user.lower() in ("", "root", "0"),
        exposed_ports=ports,
        packages=packages,
        entrypoint=entrypoint,
        cmd=cmd,
        has_healthcheck=bool(df.of("HEALTHCHECK")),
        waste_bytes_note=f"{orphan_count} deletion(s) that cannot shrink the image" if orphan_count else "",
    )

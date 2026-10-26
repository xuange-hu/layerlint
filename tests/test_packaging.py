"""Packaging contract guard.

Learned the hard way on another project: CI installs `.[all]`, so a console
script whose module imports something from an optional extra builds green and
then explodes for everyone doing a plain `pip install`. These assertions read
pyproject.toml and the AST instead of installing anything.

Also the zero-dependency promise: every core module must import only stdlib, so
`pip install layerlint` cannot fail on a missing extra.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python <= 3.10: tomllib landed in 3.11
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _pytoml as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src"


def load_config() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def scripts() -> dict[str, str]:
    return load_config()["project"]["scripts"]


def _req_name(requirement: str) -> str:
    return re.split(r"[<>=!~;\[\s]", requirement.strip(), maxsplit=1)[0].strip().lower()


def _module_of(target: str) -> str:
    return target.split(":")[0]


def _third_party_imports(module_path: Path) -> set[str]:
    """Top-level module names imported at module scope (not inside a function)."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return {n for n in names if n not in sys.stdlib_module_names}


def test_every_console_script_resolves():
    for name, target in scripts().items():
        module_path = SRC / Path(_module_of(target).replace(".", "/")).with_suffix(".py")
        assert module_path.exists(), f"{name} -> missing {module_path}"
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        functions = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
        _, _, func = target.partition(":")
        assert func in functions, f"{target}: no function {func}"


def test_base_install_does_not_need_optional_deps():
    """The dependency bug this file exists to prevent."""
    config = load_config()
    base = {_req_name(d) for d in config["project"]["dependencies"]}
    extras = {k.lower(): v for k, v in config["project"].get("optional-dependencies", {}).items()}
    for name, target in scripts().items():
        allowed = set(base)
        for candidate in {name.lower(), name.lower().rsplit("-", 1)[-1]}:
            if candidate in extras:
                allowed |= {_req_name(r) for r in extras[candidate]}
        module_path = SRC / Path(_module_of(target).replace(".", "/")).with_suffix(".py")
        missing = {
            mod
            for mod in _third_party_imports(module_path)
            if mod.lower() not in allowed and mod != "layerlint"
        }
        assert not missing, f"{name} needs {sorted(missing)} which is not an install dependency"


def test_core_modules_are_stdlib_only():
    core = ["model", "parse", "layers", "rules", "analyze", "render", "sarif", "demo", "cli"]
    for name in core:
        path = SRC / "layerlint" / f"{name}.py"
        third_party = {m for m in _third_party_imports(path) if m != "layerlint"}
        assert not third_party, f"{name}.py pulls in {sorted(third_party)}"


def test_mcp_server_is_the_only_module_needing_mcp():
    src = (SRC / "layerlint" / "mcp_server.py").read_text(encoding="utf-8")
    assert "import mcp" in src
    # ...and no other core module mentions it at all.
    for name in ["model", "parse", "layers", "rules", "analyze", "render", "sarif", "demo", "cli"]:
        assert "import mcp" not in (SRC / "layerlint" / f"{name}.py").read_text(encoding="utf-8")


def test_mcp_server_imports_mcp_lazily():
    """If it imported mcp at module scope, `pip install layerlint` would break."""
    src = (SRC / "layerlint" / "mcp_server.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    top_level: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top_level.add(node.module.split(".")[0])
    assert "mcp" not in top_level
    assert "def build_server" in src


def test_mcp_version_is_pinned_below_2():
    """mcp 2.x renamed FastMCP to MCPServer; the server is written for 1.x."""
    extras = load_config()["project"]["optional-dependencies"]["mcp"]
    assert any("mcp>=" in d and "<2" in d for d in extras), extras


def test_base_dependencies_are_empty():
    deps = load_config()["project"].get("dependencies", [])
    assert deps == [], f"core must stay zero-dependency, got {deps}"


def test_version_matches_init():
    project = load_config()["project"]
    init = (SRC / "layerlint" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{project["version"]}"' in init


def test_src_layout_is_used():
    cfg = load_config()
    joined = " ".join(cfg["build-system"]["requires"]).lower()
    assert "setuptools" in joined, "build backend must be declared"
    find = cfg["tool"]["setuptools"]["packages"]["find"]
    assert find["where"] == ["src"]


def test_tests_directory_is_not_packaged():
    packages = load_config()["tool"]["setuptools"]["packages"]
    assert packages["find"]["where"] == ["src"]


def test_mcp_entry_point_declared():
    assert "layerlint-mcp" in scripts()
    assert scripts()["layerlint-mcp"].endswith("mcp_server:main")


def test_readme_mentions_the_one_liner():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "layerlint demo" in readme
    assert load_config()["project"]["version"] in readme

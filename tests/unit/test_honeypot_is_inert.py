"""CLAUDE.md §2, enforced at import level: the honeypot synthesizes records, never programs.

The companion of the planned `test_case3_is_inert.py`. A honeypot module that grew a subprocess
call, a socket, or an `exec` would be a different kind of module than the one this project is
allowed to contain, and that change would be easy to make by accident while "improving realism".
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

HONEYPOT = Path(__file__).resolve().parents[2] / "src" / "bsfr_sh" / "honeypot"
MODULES = sorted(HONEYPOT.glob("*.py"))

#: Anything that could run, fetch or deserialise code.
FORBIDDEN_IMPORTS = {
    "subprocess",
    "socket",
    "ctypes",
    "urllib",
    "http",
    "requests",
    "pickle",
    "shutil",
    "importlib",
    "multiprocessing",
    "resource",
    "signal",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen", "spawn"}

#: `corpus.py` writes the CSV corpus, which is the one legitimate filesystem use in this package.
FILE_IO_ALLOWED = {"corpus.py"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_no_module_can_run_download_or_deserialise_anything(path: Path) -> None:
    tree = _tree(path)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & FORBIDDEN_IMPORTS, (
        f"{path.name} imports {sorted(imported & FORBIDDEN_IMPORTS)}"
    )

    called = {
        node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert not called & FORBIDDEN_CALLS, f"{path.name} calls {sorted(called & FORBIDDEN_CALLS)}"


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_only_the_corpus_writer_touches_the_filesystem(path: Path) -> None:
    if path.name in FILE_IO_ALLOWED:
        return
    called = {
        node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        for node in ast.walk(_tree(path))
        if isinstance(node, ast.Call)
    }
    assert not called & {"open", "write_bytes", "write_text", "mkdir"}, f"{path.name} writes files"


def test_a_sample_carries_no_binary_payload() -> None:
    """Feature vectors and digests only: nothing in a sample is a blob that could be content."""
    from m3b_harness import raw_draw

    for sample in raw_draw(50):
        for value in sample.counters.values():
            assert isinstance(value, float)
        assert all(isinstance(name, str) for name in sample.unobserved)
        assert not any(
            isinstance(getattr(sample, field), bytes) for field in ("sample_id", "label", "profile")
        )

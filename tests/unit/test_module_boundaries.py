"""Conventions from CLAUDE.md §3 and §7, enforced in the fast test loop rather than in review.

`make lint` catches some of this, but `make test` is what runs on every iteration, and a
convention that is only checked at lint time is a convention that gets broken for an afternoon.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "bsfr_sh"
PY_FILES = sorted(SRC.rglob("*.py"))

#: The only module allowed to import hashlib is `crypto.hashing`, which does not exist yet: M1
#: builds it. Until then `util.config` needs a digest for the config hash and holds the single
#: exemption. When M1 lands, `crypto/hashing.py` joins this set and `util/config.py` leaves it.
HASHLIB_ALLOWED = {"util/config.py"}


def _rel(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".")[0])
    return modules


def _imported_paths(tree: ast.Module) -> set[str]:
    """Full dotted module names, for checking intra-package dependency direction."""
    paths: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            paths.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            paths.add(node.module)
    return paths


@pytest.mark.parametrize("path", PY_FILES, ids=_rel)
def test_no_print_calls(path: Path) -> None:
    """CLAUDE.md §7 — no print; use util.logging. AST, so docstrings do not false-positive."""
    calls = [
        node
        for node in ast.walk(_tree(path))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
    ]
    assert not calls, f"{_rel(path)} calls print at line(s) {[c.lineno for c in calls]}"


@pytest.mark.parametrize("path", PY_FILES, ids=_rel)
def test_hashlib_is_not_called_outside_the_allowed_modules(path: Path) -> None:
    """CLAUDE.md §7 — hashing is always SHA-256 via `crypto.hashing.h()`.

    Two modules hashing through two different code paths is how a Merkle root and a block hash
    end up disagreeing about the same bytes.
    """
    if "hashlib" in _imported_modules(_tree(path)):
        assert _rel(path) in HASHLIB_ALLOWED, (
            f"{_rel(path)} imports hashlib; route it through crypto.hashing.h() "
            f"(allowed today: {sorted(HASHLIB_ALLOWED)})"
        )


@pytest.mark.parametrize("path", PY_FILES, ids=_rel)
def test_util_depends_on_nothing_else_in_the_package(path: Path) -> None:
    """docs/ARCHITECTURE.md dependency direction: util <- crypto <- blockchain <- consensus.

    A back-import from `util` into `crypto` is the architectural bug the doc warns about, and it
    is easiest to introduce exactly here, while reaching for a hash function.
    """
    if not _rel(path).startswith("util/"):
        return
    internal = {mod for mod in _imported_paths(_tree(path)) if mod.startswith("bsfr_sh")}
    offenders = {mod for mod in internal if not mod.startswith("bsfr_sh.util")}
    assert not offenders, f"{_rel(path)} imports {sorted(offenders)}; util may not depend upward"


def test_serialization_does_not_hash_or_sign() -> None:
    """M0 scope boundary: `util.serialization` defines the encoding only.

    Hashing is M1 (`crypto.hashing`) and signing is M1/M2. Keeping them apart is what allows the
    encoding to be tested — and pinned — before any crypto exists.
    """
    imports = _imported_modules(_tree(SRC / "util" / "serialization.py"))
    assert not imports & {"hashlib", "hmac", "secrets", "cryptography"}


def test_every_package_has_an_init() -> None:
    for package in sorted(p for p in SRC.iterdir() if p.is_dir() and not p.name.startswith("__")):
        assert (package / "__init__.py").exists(), f"{package.name} is not an importable package"

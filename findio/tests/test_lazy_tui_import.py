"""
ARCHITECTURE.md — textual / rich must stay optional.

Library consumers (scripts, other tools) that never call pick_interactive() must
not be forced to install textual. We enforce this by simulating a venv
without textual installed and importing findio from scratch.

Technique: blank-out textual/rich in sys.modules and block them from being
reimported via a finder that raises ImportError. Then fresh-import `findio`
and assert the whole public surface still works.
"""

from __future__ import annotations

import importlib
import sys

import pytest


_BANNED_PREFIXES = ("textual", "rich", "markdown_it", "mdurl", "linkify_it", "platformdirs")


class _BlockingFinder:
    """Raise ImportError on any attempt to import textual / rich / their deps."""

    def find_spec(self, name, path=None, target=None):
        if any(name == p or name.startswith(p + ".") for p in _BANNED_PREFIXES):
            raise ImportError(f"simulated missing package: {name}")
        return None


@pytest.fixture
def no_textual(monkeypatch):
    # Drop already-imported copies so the fresh import re-runs binding logic.
    for mod in list(sys.modules):
        if any(mod == p or mod.startswith(p + ".") for p in _BANNED_PREFIXES):
            monkeypatch.delitem(sys.modules, mod, raising=False)
    # Also drop findio / findio.ui so __init__ re-runs without cache.
    for mod in list(sys.modules):
        if mod == "findio" or mod.startswith("findio."):
            monkeypatch.delitem(sys.modules, mod, raising=False)
    finder = _BlockingFinder()
    monkeypatch.setattr(sys, "meta_path", [finder] + sys.meta_path)
    yield


def test_findio_imports_without_textual(no_textual):
    # The whole public API must be reachable with textual simulated-missing.
    findio = importlib.import_module("findio")
    assert hasattr(findio, "FINDIO_API_VERSION")
    assert hasattr(findio, "Scanner")
    assert hasattr(findio, "DeviceRegistry")
    assert hasattr(findio, "resolve_many")
    assert hasattr(findio, "pick_interactive")
    assert hasattr(findio, "pick_by_label")


def test_scanner_works_without_textual(no_textual):
    findio = importlib.import_module("findio")
    # Instantiation must not trigger textual import.
    s = findio.Scanner()
    assert hasattr(s, "scan")


def test_pick_interactive_raises_import_error_when_textual_missing(no_textual):
    findio = importlib.import_module("findio")
    with pytest.raises(ImportError) as exc:
        findio.pick_interactive()
    # Error message must point the user at the install command.
    assert "textual" in str(exc.value).lower()
    assert "pip install" in str(exc.value).lower()

"""
Public-API contract test — the scaffold's only live spec.

Asserts:
  1. FINDIO_API_VERSION exists and is a MAJOR.MINOR.PATCH string.
  2. `Device` has exactly the 12 documented fields (freeze the shape early).
  3. Every public name in __all__ is importable from `findio`.
  4. Stubs raise NotImplementedError so callers fail loudly, not silently.

This is the interop contract scripts and other tools will depend on.
Breaking any assertion here = bump FINDIO_API_VERSION per ARCHITECTURE.md.
"""

from __future__ import annotations

import re

import pytest

import findio


# --------------------------------------------------------------------------- #
# Version                                                                     #
# --------------------------------------------------------------------------- #


def test_api_version_is_semver():
    assert hasattr(findio, "FINDIO_API_VERSION")
    assert re.match(r"^\d+\.\d+\.\d+$", findio.FINDIO_API_VERSION), (
        f"FINDIO_API_VERSION must be MAJOR.MINOR.PATCH, got {findio.FINDIO_API_VERSION!r}"
    )


# --------------------------------------------------------------------------- #
# Device dataclass — the interop contract                                     #
# --------------------------------------------------------------------------- #


EXPECTED_DEVICE_FIELDS = {
    "ip",
    "mac",
    "iface",
    "label",
    "hostname",
    "vendor",
    "ssh_user",
    "ssh_port",
    "notes",
    "is_test_system",
    "first_seen",
    "last_seen",
}


def test_device_has_exact_field_set():
    from dataclasses import fields

    actual = {f.name for f in fields(findio.Device)}
    assert actual == EXPECTED_DEVICE_FIELDS, (
        "Device field set drifted. If intentional, bump FINDIO_API_VERSION "
        "(MAJOR for rename/remove, MINOR for add) and update this test."
    )


def test_device_is_frozen():
    d = findio.Device(ip="192.0.2.1")
    with pytest.raises(Exception):  # FrozenInstanceError subclasses AttributeError
        d.ip = "192.0.2.2"  # type: ignore[misc]


def test_device_display_name_and_ssh_target():
    d = findio.Device(ip="192.0.2.1", mac="AA:BB:CC:DD:EE:FF")
    assert d.display_name == "AA:BB:CC:DD:EE:FF"
    assert d.ssh_target == "192.0.2.1"  # no user set → bare ip

    d2 = findio.Device(ip="192.0.2.1", ssh_user="alice", label="bench-2")
    assert d2.display_name == "bench-2"
    assert d2.ssh_target == "alice@192.0.2.1"


def test_device_to_dict_roundtrip():
    d = findio.Device(ip="192.0.2.1", mac="AA:BB:CC:DD:EE:FF", label="bench-2")
    out = d.to_dict()
    assert out["ip"] == "192.0.2.1"
    assert out["label"] == "bench-2"
    assert set(out.keys()) == EXPECTED_DEVICE_FIELDS


# --------------------------------------------------------------------------- #
# Public surface — names promised in __all__ must be importable               #
# --------------------------------------------------------------------------- #


EXPECTED_PUBLIC_NAMES = {
    "FINDIO_API_VERSION",
    "Device",
    "ScanResult",
    "Diff",
    "Scanner",
    "DeviceRegistry",
    "resolve_many",
    "pick_interactive",
    "pick_by_label",
}


def test_public_surface():
    assert set(findio.__all__) == EXPECTED_PUBLIC_NAMES, (
        "findio.__all__ drifted. Removing a name = MAJOR bump; "
        "adding = MINOR bump. Update this test in the same commit."
    )
    for name in EXPECTED_PUBLIC_NAMES:
        assert hasattr(findio, name), f"findio.{name} not exported"


# --------------------------------------------------------------------------- #
# Stubs must raise — silent returns would let consumers drift                 #
# --------------------------------------------------------------------------- #


def test_scanner_is_live_class():
    # Phase 1: Scanner is no longer a stub — construct without network work.
    s = findio.Scanner()
    assert hasattr(s, "scan")
    assert hasattr(s, "scan_all")


def test_registry_is_live_class(tmp_path):
    # Phase 2: real SQLite registry. Isolated via FINDIO_STATE_DIR equivalent.
    reg = findio.DeviceRegistry(state_dir=str(tmp_path))
    assert hasattr(reg, "record_scan")
    assert hasattr(reg, "diff_against_baseline")
    reg.close()


def test_pick_interactive_is_live():
    # Phase 4: live. We don't run it here (needs a TTY) — just confirm the
    # function no longer raises NotImplementedError on access. The
    # test_lazy_tui_import suite covers the no-textual path.
    assert callable(findio.pick_interactive)
    assert findio.pick_interactive.__doc__ and "TUI" in findio.pick_interactive.__doc__


def test_pick_by_label_unknown_returns_none(tmp_path):
    # Phase 2: pick_by_label lives behind DeviceRegistry.get_by_label.
    assert findio.pick_by_label("no-such-label", state_dir=str(tmp_path)) is None

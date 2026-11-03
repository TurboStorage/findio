"""
FindIO — network device discovery, delta tracking, SSH launcher.

PUBLIC API (locked by FINDIO_API_VERSION, see ARCHITECTURE.md):

    from findio import (
        FINDIO_API_VERSION,
        Device,
        ScanResult,
        Diff,
        Scanner,
        DeviceRegistry,
        pick_interactive,
        pick_by_label,
    )

External consumers (scripts, other tools) must import from `findio` only.
Internal submodules (findio.scanner, findio.ui.tui, ...) are not a stable surface.
"""

from __future__ import annotations

from typing import Optional

from .models import Device, ScanResult, Diff
from .scanner import Scanner
from .registry import DeviceRegistry
from .resolve import resolve_many

# ---------------------------------------------------------------------------
# API version — bump on Device field changes or public-surface changes.
# MAJOR = breaking (field removed/renamed, semantics changed)
# MINOR = additive (new optional field, new function, new exit code)
# PATCH = fix only (no contract change)
# Keep in sync with ARCHITECTURE.md "JSON schema" section.
# ---------------------------------------------------------------------------
FINDIO_API_VERSION = "1.2.0"


# ---------------------------------------------------------------------------
# Public API — stubs. Phase 1+ replaces these with real implementations.
# Every name below is a promise to consumers; removing one is a MAJOR bump.
# ---------------------------------------------------------------------------


def pick_interactive(state_dir: Optional[str] = None) -> Optional[Device]:
    """Open the Textual TUI picker. Returns chosen Device, or None if cancelled.

    Lazy-imports textual/rich — those deps are optional for library consumers
    that never call this function. See ARCHITECTURE.md.
    """
    from .ui.tui import run_tui  # local import keeps textual out of the library path

    return run_tui(state_dir=state_dir)


def pick_by_label(label: str, state_dir: Optional[str] = None) -> Optional[Device]:
    """Non-interactive resolve of an operator label to its Device record.

    Returns None if the label is unknown. The returned Device carries
    the most recent sighting (last_ip / last_iface). Callers decide
    whether to trigger a fresh scan if last_seen is stale.
    """
    with DeviceRegistry(state_dir=state_dir) as reg:
        return reg.get_by_label(label)


__all__ = [
    "FINDIO_API_VERSION",
    "Device",
    "ScanResult",
    "Diff",
    "Scanner",
    "DeviceRegistry",
    "resolve_many",
    "pick_interactive",
    "pick_by_label",
]

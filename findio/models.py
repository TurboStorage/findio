"""
Data models for FindIO.

The `Device` dataclass is the interop contract between:
  - The standalone FindIO CLI / TUI
  - The FindIO Python library (imported by scripts or other tools)
  - The JSON CLI (`findio pick --json`, `findio scan --json`)

FROZEN. Field changes bump FINDIO_API_VERSION in `findio/__init__.py`.
See ARCHITECTURE.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass(frozen=True)
class Device:
    """
    One known device on a scanned subnet.

    Keyed by MAC (stable across DHCP renewals). If MAC is unknown
    (rare — host ARP-silent or fallback scan), `mac` is None and
    identity falls back to (iface, ip).

    Time fields are ISO-8601 UTC strings. Using strings (not datetime)
    keeps the JSON contract symmetric with Python without timezone
    gymnastics at the wire boundary.
    """

    ip: str
    mac: Optional[str] = None
    iface: Optional[str] = None

    label: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None

    ssh_user: Optional[str] = None
    ssh_port: int = 22

    notes: Optional[str] = None
    is_test_system: bool = False

    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize for JSON CLI output. Schema locked by FINDIO_API_VERSION."""
        return asdict(self)

    @property
    def display_name(self) -> str:
        """Best-available human identifier. Used by TUI + picker output."""
        return self.label or self.hostname or self.mac or self.ip

    @property
    def ssh_target(self) -> str:
        """`user@ip` form for os.execvp / subprocess. ssh_user defaults handled by caller."""
        if self.ssh_user:
            return f"{self.ssh_user}@{self.ip}"
        return self.ip


@dataclass(frozen=True)
class ScanResult:
    """Return type from `Scanner.scan()`. One scan of one interface."""

    iface: str
    cidr: str
    started_at: str
    finished_at: str
    devices: tuple[Device, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Diff:
    """
    Return type from `DeviceRegistry.diff_*()`.

    Each bucket holds Device records snapshotted at the moment of diff.
    `changed` pairs are (before, after) with same MAC, different IP.
    """

    new: tuple[Device, ...] = field(default_factory=tuple)
    changed: tuple[tuple[Device, Device], ...] = field(default_factory=tuple)
    lost: tuple[Device, ...] = field(default_factory=tuple)
    returned: tuple[Device, ...] = field(default_factory=tuple)
    unchanged: tuple[Device, ...] = field(default_factory=tuple)

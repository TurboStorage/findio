"""
Name resolution — layered, each layer independent, first hit wins.

Priority (highest → lowest):
  1. Operator label from registry         (handled at CLI layer, not here)
  2. Reverse DNS (PTR)                     — socket.gethostbyaddr, ~50-500ms
  3. SSH banner grab (TCP 22)              — most BMCs identify themselves here
  4. OUI vendor from MAC                   — always-offline, from data/oui.csv
  5. Fallback: None

mDNS + NetBIOS + HTTPS cert CN are deferred to Phase 7 (need opt-in deps or
non-trivial packet crafting; the three probes here already cover most cases).

Each probe runs with a short timeout (default 500 ms) and degrades silently.
`resolve_many()` parallelizes across devices via ThreadPoolExecutor, and within
each device the probes run sequentially (rDNS → SSH banner) — cheap-first wins.

Public API:
  resolve_vendor(mac)                 → Optional[str]
  resolve_hostname(ip, timeout_ms)    → Optional[str]
  grab_banner(ip, port, timeout_ms)   → Optional[str]
  classify_banner(banner)             → Optional[str]    # BMC family
  resolve_many(devices, timeout_ms, workers) → tuple[Device, ...]
"""

from __future__ import annotations

import csv
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .models import Device


# --------------------------------------------------------------------------- #
# Tunables                                                                    #
# --------------------------------------------------------------------------- #

DEFAULT_PROBE_TIMEOUT_MS = 500
DEFAULT_RESOLVE_WORKERS = 32
BANNER_PORT_DEFAULT = 22
BANNER_READ_BYTES = 256


# --------------------------------------------------------------------------- #
# OUI lookup                                                                  #
# --------------------------------------------------------------------------- #


_OUI_PREFIX_RE = re.compile(r"^[0-9A-Fa-f]{6}$")
_BUNDLED_OUI_PATH = Path(__file__).parent / "data" / "oui.csv"


def _user_oui_path() -> Optional[Path]:
    """Per-user override at ~/.findio/oui.csv (or $FINDIO_STATE_DIR/oui.csv)."""
    state_dir = os.environ.get("FINDIO_STATE_DIR")
    if state_dir:
        p = Path(state_dir).expanduser() / "oui.csv"
    else:
        p = Path.home() / ".findio" / "oui.csv"
    return p if p.exists() else None


def _parse_oui_row(row: list[str]) -> Optional[tuple[str, str]]:
    """Accept FindIO's curated format OR a common IEEE MA-L CSV shape.

    Supported inputs:
      - FindIO: `PREFIX_6HEX,VENDOR`
      - IEEE MA-L: `Registry,Assignment,Organization Name,Organization Address`
        where Assignment is a 6-hex prefix.
      - Wireshark manuf: prefix as 'XX:XX:XX' with optional mask; we ignore mask.
    """
    if not row:
        return None
    first = row[0].strip()
    # IEEE MA-L data row: 4 cols, col[1] is a 6-hex assignment.
    if len(row) >= 3 and _OUI_PREFIX_RE.match(row[1].strip()):
        prefix = row[1].strip().upper()
        vendor = row[2].strip()
    else:
        prefix_raw = first.replace(":", "").replace("-", "").upper()
        if not _OUI_PREFIX_RE.match(prefix_raw):
            return None  # header row or malformed — skip silently
        prefix = prefix_raw
        vendor = row[1].strip() if len(row) > 1 else ""
    if not vendor:
        return None
    return prefix, vendor


@lru_cache(maxsize=1)
def _oui_table() -> dict[str, str]:
    """Load OUI CSV once and cache. User override wins over bundled fallback."""
    table: dict[str, str] = {}
    for path in (_BUNDLED_OUI_PATH, _user_oui_path()):
        if path is None or not path.exists():
            continue
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                parsed = _parse_oui_row(row)
                if parsed is None:
                    continue
                prefix, vendor = parsed
                table[prefix] = vendor
    return table


def resolve_vendor(mac: Optional[str]) -> Optional[str]:
    """OUI lookup. Returns vendor name or None. Always cheap, always offline."""
    if not mac:
        return None
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    if not _OUI_PREFIX_RE.match(prefix):
        return None
    return _oui_table().get(prefix)


# --------------------------------------------------------------------------- #
# Reverse DNS                                                                 #
# --------------------------------------------------------------------------- #


def _rdns_raw(ip: str) -> Optional[str]:
    try:
        host, *_ = socket.gethostbyaddr(ip)
        return host or None
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_hostname(ip: str, timeout_ms: int = DEFAULT_PROBE_TIMEOUT_MS) -> Optional[str]:
    """rDNS with a hard wall-clock timeout (gethostbyaddr ignores socket.setdefaulttimeout)."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_rdns_raw, ip)
        try:
            return fut.result(timeout=timeout_ms / 1000.0)
        except Exception:  # noqa: BLE001 — timeout or any lookup error → None
            return None


# --------------------------------------------------------------------------- #
# SSH banner grab                                                             #
# --------------------------------------------------------------------------- #


def grab_banner(
    ip: str, port: int = BANNER_PORT_DEFAULT, timeout_ms: int = DEFAULT_PROBE_TIMEOUT_MS
) -> Optional[str]:
    """Open TCP, read the greeting. SSH servers send banner unprompted.

    For non-SSH ports this returns whatever the peer sends first (useful for
    HTTP servers too). Empty banners return None.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout_ms / 1000.0) as s:
            s.settimeout(timeout_ms / 1000.0)
            data = s.recv(BANNER_READ_BYTES)
    except (OSError, socket.timeout):
        return None
    if not data:
        return None
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return None
    # SSH banners end with \r\n; take the first line only.
    return text.splitlines()[0] if text else None


# --------------------------------------------------------------------------- #
# BMC fingerprint library                                                     #
# --------------------------------------------------------------------------- #


# Order matters — more specific patterns before less specific.
_BMC_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"hpiLO|mod_sshd", re.I), "HPE iLO"),
    (re.compile(r"Dell.*iDRAC|iDRAC", re.I), "Dell iDRAC"),
    (re.compile(r"SMCsshd", re.I), "Supermicro BMC"),
    (re.compile(r"OpenBMC", re.I), "OpenBMC"),
    (re.compile(r"AMI.*Megarac|Megarac", re.I), "AMI Megarac"),
    (re.compile(r"ASPEED|AST\d{4}", re.I), "ASPEED BMC"),
    (re.compile(r"ProLiant", re.I), "HPE ProLiant"),
    (re.compile(r"Dropbear", re.I), "Dropbear SSH (embedded)"),
)


def classify_banner(banner: Optional[str]) -> Optional[str]:
    """Return BMC/embedded-family label from an SSH banner, or None."""
    if not banner:
        return None
    for pattern, label in _BMC_PATTERNS:
        if pattern.search(banner):
            return label
    return None


# --------------------------------------------------------------------------- #
# Orchestrator                                                                #
# --------------------------------------------------------------------------- #


def _resolve_one(
    device: Device, *, timeout_ms: int, probe_ssh: bool
) -> Device:
    """Enrich a single device. Probes run sequentially (cheap-first).

    Fields written (when a hit lands):
      hostname  — rDNS result
      vendor    — OUI name, OR BMC family when SSH banner fingerprints one
                  (BMC family wins: it's more specific than OUI)
      notes     — SSH banner captured verbatim when present
    """
    hostname = resolve_hostname(device.ip, timeout_ms=timeout_ms)
    vendor = resolve_vendor(device.mac)

    banner: Optional[str] = None
    bmc_family: Optional[str] = None
    if probe_ssh:
        banner = grab_banner(device.ip, timeout_ms=timeout_ms)
        bmc_family = classify_banner(banner)

    final_vendor = bmc_family or vendor
    notes = banner if banner else device.notes

    return Device(
        ip=device.ip,
        mac=device.mac,
        iface=device.iface,
        label=device.label,
        hostname=hostname or device.hostname,
        vendor=final_vendor or device.vendor,
        ssh_user=device.ssh_user,
        ssh_port=device.ssh_port,
        notes=notes,
        is_test_system=device.is_test_system,
        first_seen=device.first_seen,
        last_seen=device.last_seen,
    )


def resolve_many(
    devices: tuple[Device, ...],
    *,
    timeout_ms: int = DEFAULT_PROBE_TIMEOUT_MS,
    workers: int = DEFAULT_RESOLVE_WORKERS,
    probe_ssh: bool = True,
) -> tuple[Device, ...]:
    """Enrich devices in parallel. Preserves input order. Never raises."""
    if not devices:
        return ()
    out: list[Optional[Device]] = [None] * len(devices)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_resolve_one, d, timeout_ms=timeout_ms, probe_ssh=probe_ssh): i
            for i, d in enumerate(devices)
        }
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                out[i] = fut.result()
            except Exception:  # noqa: BLE001 — keep the original row on failure
                out[i] = devices[i]
    return tuple(d or devices[i] for i, d in enumerate(out))

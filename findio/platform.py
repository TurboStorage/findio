"""
Platform shim — macOS vs Linux differences isolated here.

Zero-dep: stdlib only. Parses `ifconfig` / `ip` / `arp` / `ip neigh` output.

Public functions:
  current_platform()             → "darwin" | "linux" | "unsupported"
  list_interfaces()              → tuple[dict] — {name, ip, cidr, is_up}
  read_arp_table()               → dict[ip] → (mac, iface)
  parse_macos_arp(text)          → dict[ip] → (mac, iface)     # pure, testable
  parse_linux_arp(text)          → dict[ip] → (mac, iface)     # pure, testable
  parse_macos_ifconfig(text)     → tuple[dict]                 # pure, testable
  normalize_mac(raw)             → "AA:BB:CC:DD:EE:FF" | None
"""

from __future__ import annotations

import platform as _platform
import re
import subprocess
from typing import Literal, Optional

PlatformName = Literal["darwin", "linux", "unsupported"]


# Virtual / tunnel / Apple-internal interface name prefixes to ignore when
# enumerating scannable interfaces. Users on VPNs or Tailscale will see
# those interfaces here too — excluded by default.
_VIRTUAL_PREFIXES = (
    "lo",
    "utun",
    "awdl",
    "llw",
    "anpi",
    "ap",
    "bridge",
    "gif",
    "stf",
    "docker",
    "br-",
    "vmnet",
    "vnic",
    "vboxnet",
    "tun",
    "tap",
)


def current_platform() -> PlatformName:
    system = _platform.system().lower()
    if system == "darwin":
        return "darwin"
    if system == "linux":
        return "linux"
    return "unsupported"


# --------------------------------------------------------------------------- #
# MAC normalization                                                           #
# --------------------------------------------------------------------------- #


_MAC_OCTET_RE = re.compile(r"^[0-9a-fA-F]{1,2}$")


def normalize_mac(raw: str) -> Optional[str]:
    """Return canonical AA:BB:CC:DD:EE:FF, or None if unparseable / not a real unicast.

    Filters out multicast/broadcast addresses (I/G bit set on first octet)
    so broadcast `ff:ff:ff:ff:ff:ff` and multicast `01:00:5e:*` rows drop
    at parse time — they are not endpoints we can SSH into.
    """
    if not raw:
        return None
    parts = raw.strip().split(":")
    if len(parts) != 6:
        return None
    padded = []
    for p in parts:
        if not _MAC_OCTET_RE.match(p):
            return None
        padded.append(p.zfill(2).upper())
    first = int(padded[0], 16)
    if first & 0x01:  # multicast/broadcast — not a real endpoint
        return None
    return ":".join(padded)


# --------------------------------------------------------------------------- #
# ARP table parsing — pure string → dict (testable without subprocess)        #
# --------------------------------------------------------------------------- #


# macOS:  ? (192.0.2.1) at aa:bb:cc:dd:ee:ff on en5 ifscope [ethernet]
_MACOS_ARP_RE = re.compile(
    r"^\?\s+\((?P<ip>[\d.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:\(\)incomplete\s]+?)\s+on\s+(?P<iface>\S+)"
)

# Linux:  192.0.2.1 dev enp3s0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
_LINUX_ARP_RE = re.compile(
    r"^(?P<ip>[\d.]+)\s+dev\s+(?P<iface>\S+)\s+lladdr\s+(?P<mac>[0-9a-fA-F:]+)\s+(?P<state>\w+)"
)

_LINUX_ACCEPTED_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}


def parse_macos_arp(text: str) -> dict[str, tuple[str, str]]:
    """Parse `arp -an` output. Returns {ip: (mac, iface)}.

    Skips (incomplete) rows and multicast/broadcast MACs.
    """
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        m = _MACOS_ARP_RE.match(line)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac is None:  # incomplete, multicast, broadcast, or malformed
            continue
        out[m.group("ip")] = (mac, m.group("iface"))
    return out


def parse_linux_arp(text: str) -> dict[str, tuple[str, str]]:
    """Parse `ip neigh show` output. Returns {ip: (mac, iface)}.

    Skips FAILED / INCOMPLETE rows (no `lladdr`) and multicast/broadcast MACs.
    """
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        m = _LINUX_ARP_RE.match(line)
        if not m:
            continue
        if m.group("state") not in _LINUX_ACCEPTED_STATES:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac is None:
            continue
        out[m.group("ip")] = (mac, m.group("iface"))
    return out


def read_arp_table() -> dict[str, tuple[str, str]]:
    """Invoke the platform's ARP tool and parse it. Empty dict on failure."""
    plat = current_platform()
    try:
        if plat == "darwin":
            text = subprocess.run(
                ["arp", "-an"], capture_output=True, text=True, timeout=5
            ).stdout
            return parse_macos_arp(text)
        if plat == "linux":
            try:
                text = subprocess.run(
                    ["ip", "neigh", "show"], capture_output=True, text=True, timeout=5
                ).stdout
                return parse_linux_arp(text)
            except FileNotFoundError:
                # iproute2 absent (rare on modern distros) — fall back to legacy arp
                text = subprocess.run(
                    ["arp", "-an"], capture_output=True, text=True, timeout=5
                ).stdout
                return parse_macos_arp(text)  # legacy arp output matches macOS format
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return {}
    return {}


# --------------------------------------------------------------------------- #
# Interface enumeration                                                       #
# --------------------------------------------------------------------------- #


_MACOS_IFCONFIG_HEADER_RE = re.compile(r"^(?P<name>\S+?):\s+flags=\w+<(?P<flags>[^>]*)>")
_MACOS_IFCONFIG_INET_RE = re.compile(
    r"^\s*inet\s+(?P<ip>[\d.]+)\s+netmask\s+0x(?P<mask>[0-9a-fA-F]{8})"
)

# Linux: `ip -4 -o addr show`
# 3: enp3s0    inet 192.0.2.5/24 brd 192.0.2.255 scope global dynamic enp3s0 ...
_LINUX_IPADDR_RE = re.compile(
    r"^\d+:\s+(?P<name>\S+)\s+inet\s+(?P<ip>[\d.]+)/(?P<prefix>\d+)"
)


def _is_virtual_name(name: str) -> bool:
    return name.startswith(_VIRTUAL_PREFIXES)


def _hex_netmask_to_prefix(hex_mask: str) -> int:
    """0xffffff00 → 24."""
    n = int(hex_mask, 16)
    return bin(n).count("1")


def parse_macos_ifconfig(text: str) -> tuple[dict, ...]:
    """Parse `ifconfig` output. Returns tuple[{name, ip, cidr, is_up}]."""
    current: Optional[dict] = None
    results: list[dict] = []
    for line in text.splitlines():
        header = _MACOS_IFCONFIG_HEADER_RE.match(line)
        if header:
            # flush previous
            if current and current.get("ip"):
                results.append(current)
            flags = header.group("flags").split(",")
            is_up = "UP" in flags and "RUNNING" in flags
            current = {
                "name": header.group("name"),
                "ip": None,
                "cidr": None,
                "is_up": is_up,
            }
            continue
        if current is None:
            continue
        inet = _MACOS_IFCONFIG_INET_RE.match(line)
        if inet and current.get("ip") is None:  # first inet wins per interface
            prefix = _hex_netmask_to_prefix(inet.group("mask"))
            current["ip"] = inet.group("ip")
            current["cidr"] = f"{inet.group('ip')}/{prefix}"
    if current and current.get("ip"):
        results.append(current)
    return tuple(
        r for r in results
        if r["is_up"]
        and not _is_virtual_name(r["name"])
        and not r["ip"].startswith("127.")
    )


def parse_linux_ipaddr(text: str) -> tuple[dict, ...]:
    """Parse `ip -4 -o addr show` output."""
    results: list[dict] = []
    for line in text.splitlines():
        m = _LINUX_IPADDR_RE.match(line)
        if not m:
            continue
        name = m.group("name")
        ip = m.group("ip")
        if _is_virtual_name(name) or ip.startswith("127."):
            continue
        results.append({
            "name": name,
            "ip": ip,
            "cidr": f"{ip}/{m.group('prefix')}",
            "is_up": True,  # ip -o addr only lists interfaces with an address bound
        })
    return tuple(results)


def list_interfaces() -> tuple[dict, ...]:
    """Return scannable interfaces. Non-loopback, non-virtual, UP, IPv4-bound."""
    plat = current_platform()
    try:
        if plat == "darwin":
            text = subprocess.run(
                ["ifconfig"], capture_output=True, text=True, timeout=5
            ).stdout
            return parse_macos_ifconfig(text)
        if plat == "linux":
            text = subprocess.run(
                ["ip", "-4", "-o", "addr", "show"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            return parse_linux_ipaddr(text)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return ()
    return ()

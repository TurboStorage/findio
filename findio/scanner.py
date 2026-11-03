"""
Scanner — discover devices on directly-connected subnets.

Strategy (no root):
  1. Enumerate interfaces with IPv4 + non-loopback (see `platform.list_interfaces`).
  2. Parallel ICMP sweep of the subnet to populate the kernel ARP table.
     (We don't care whether ping succeeds — an ARP reply is link-layer and
     lands in the cache even if ICMP is filtered in userspace.)
  3. Scrape ARP table (`arp -an` / `ip neigh` — see platform.py).
  4. Build `Device` rows for every (ip, mac) pair in our scanned subnet.
  5. Name/vendor resolution is layered on top by `resolve.py`.

Safety: only sweeps private/link-local ranges by default, at a bounded probe
rate. Use it only on networks you are authorized to scan.

What this cannot do (documented in README scope-honesty):
  - Find hosts that drop ICMP AND are ARP-silent (vanishingly rare on a LAN).
  - Cross VLANs the Mac isn't a member of.
  - Identify MAC-randomized clients as "same device across scans" — MAC rotation
    is the point of MAC randomization, and we key identity on MAC.
"""

from __future__ import annotations

import ipaddress
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

from . import platform as _plat
from .models import Device, ScanResult


# --------------------------------------------------------------------------- #
# Tunables                                                                    #
# --------------------------------------------------------------------------- #

DEFAULT_TIMEOUT_MS = 300     # per-host ping wait; ARP replies land well under this on LAN
DEFAULT_WORKERS = 64         # concurrent ping processes
DEFAULT_MAX_RATE = 200.0     # max pings started per second (0 = unlimited); /24 in ~1.3s
MAX_HOSTS_PER_SCAN = 1024    # /22 ceiling — refuse to sweep bigger subnets for now


# --------------------------------------------------------------------------- #
# Ping — one host, fire-and-forget                                            #
# --------------------------------------------------------------------------- #


def _ping_args(ip: str, timeout_ms: int, plat: str) -> list[str]:
    """Build the per-platform ping command. `-n` numeric, `-q` quiet, `-c 1` one echo."""
    if plat == "darwin":
        # macOS: -W is in MILLISECONDS. -t is a deadline in seconds (different).
        return ["ping", "-c", "1", "-n", "-q", "-W", str(timeout_ms), ip]
    # linux (and "unsupported" fallback — matches iputils)
    secs = max(1, (timeout_ms + 999) // 1000)
    return ["ping", "-c", "1", "-n", "-q", "-W", str(secs), ip]


def _ping(ip: str, timeout_ms: int, plat: str) -> None:
    """Fire a single ping. Return value is ignored — ARP cache is what we harvest."""
    try:
        subprocess.run(
            _ping_args(ip, timeout_ms, plat),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000.0) + 1.0,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        # Individual ping failures are normal (host offline). Scan continues.
        return


def _enumerate_hosts(cidr: str, *, allow_public: bool = False) -> tuple[str, ...]:
    """Return all host IPs in a CIDR (excluding network + broadcast for v4).

    Refuses publicly routable ranges unless `allow_public` is set: FindIO is a
    LAN tool, and sweeping address space you do not operate is not acceptable.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if not allow_public and not (net.is_private or net.is_link_local):
        raise ValueError(
            f"Refusing to sweep {cidr}: not a private/link-local range. "
            f"Only scan networks you are authorized to scan "
            f"(pass --allow-public / allow_public=True to override)."
        )
    if net.num_addresses > MAX_HOSTS_PER_SCAN + 2:
        raise ValueError(
            f"Refusing to sweep {cidr}: {net.num_addresses} hosts > "
            f"cap of {MAX_HOSTS_PER_SCAN}. Narrow the subnet or raise the cap."
        )
    return tuple(str(h) for h in net.hosts())


# --------------------------------------------------------------------------- #
# Public scan function                                                        #
# --------------------------------------------------------------------------- #


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def scan_subnet(
    iface: str,
    cidr: str,
    *,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    workers: int = DEFAULT_WORKERS,
    max_rate: float = DEFAULT_MAX_RATE,
    allow_public: bool = False,
) -> ScanResult:
    """Sweep a CIDR and return the devices visible in the ARP cache afterward.

    Pure discovery — no name resolution, no persistence. `Device.iface` is set
    from the ARP table entry (which may differ from the passed `iface` if a
    device is reachable through more than one path).
    """
    started_at = _now_iso()
    t0 = time.monotonic()

    plat = _plat.current_platform()
    hosts = _enumerate_hosts(cidr, allow_public=allow_public)

    # Parallel ICMP sweep. We intentionally don't collect results — the ARP
    # cache is the side effect we care about. Bounding with ThreadPoolExecutor
    # keeps us from forking 254+ ping processes at once.
    if hosts:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            interval = 1.0 / max_rate if max_rate and max_rate > 0 else 0.0
            next_start = time.monotonic()
            for ip in hosts:
                if interval:
                    delay = next_start - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    next_start += interval
                pool.submit(_ping, ip, timeout_ms, plat)
        # pool.__exit__ waits for all futures

    # Scrape ARP table once after the sweep settles. Tiny sleep gives the
    # kernel a beat to finalize cache entries for the last pings in flight.
    time.sleep(0.05)
    arp = _plat.read_arp_table()

    scanned_net = ipaddress.ip_network(cidr, strict=False)
    devices: list[Device] = []
    for ip, (mac, entry_iface) in arp.items():
        try:
            if ipaddress.ip_address(ip) not in scanned_net:
                continue
        except ValueError:
            continue
        devices.append(
            Device(
                ip=ip,
                mac=mac,
                iface=entry_iface,
                last_seen=started_at,
            )
        )

    devices.sort(key=lambda d: tuple(int(p) for p in d.ip.split(".")))

    finished_at = _now_iso()
    _ = t0  # kept for future perf logging
    return ScanResult(
        iface=iface,
        cidr=cidr,
        started_at=started_at,
        finished_at=finished_at,
        devices=tuple(devices),
    )


# --------------------------------------------------------------------------- #
# Scanner class — public API surface                                          #
# --------------------------------------------------------------------------- #


class Scanner:
    """Discover devices on a subnet via ICMP sweep + ARP scrape.

    Usage:
        Scanner().scan()                          # auto-pick first UP iface
        Scanner(iface="en0").scan()               # constrain to one iface
        Scanner(cidr="198.51.100.0/24").scan()     # override CIDR
        Scanner().scan_all()                      # every UP iface, list[ScanResult]
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        cidr: Optional[str] = None,
        *,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        workers: int = DEFAULT_WORKERS,
        max_rate: float = DEFAULT_MAX_RATE,
        allow_public: bool = False,
    ) -> None:
        self.iface = iface
        self.cidr = cidr
        self.timeout_ms = timeout_ms
        self.workers = workers
        self.max_rate = max_rate
        self.allow_public = allow_public

    # --- helpers ----------------------------------------------------------- #

    def _resolve_target(self) -> tuple[str, str]:
        """Pick the (iface, cidr) pair to scan. Raises if nothing is scannable."""
        ifaces = _plat.list_interfaces()
        if not ifaces:
            raise RuntimeError(
                "No scannable interfaces found (non-loopback, non-virtual, UP, IPv4)."
            )
        if self.iface:
            match = next((i for i in ifaces if i["name"] == self.iface), None)
            if match is None:
                names = ", ".join(i["name"] for i in ifaces) or "none"
                raise RuntimeError(
                    f"Interface {self.iface!r} not found or not scannable. "
                    f"Available: {names}"
                )
            return match["name"], self.cidr or match["cidr"]
        first = ifaces[0]
        return first["name"], self.cidr or first["cidr"]

    # --- public API -------------------------------------------------------- #

    def scan(self) -> ScanResult:
        iface, cidr = self._resolve_target()
        return scan_subnet(
            iface, cidr, timeout_ms=self.timeout_ms, workers=self.workers,
            max_rate=self.max_rate, allow_public=self.allow_public,
        )

    def scan_all(self) -> tuple[ScanResult, ...]:
        """Scan every UP, non-virtual IPv4 interface. Used by dual-NIC BMC setups."""
        ifaces = _plat.list_interfaces()
        return tuple(
            scan_subnet(
                i["name"], i["cidr"],
                timeout_ms=self.timeout_ms, workers=self.workers,
                max_rate=self.max_rate, allow_public=self.allow_public,
            )
            for i in ifaces
        )

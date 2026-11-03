"""
Scanner tests — unit-level, no real network.

The ICMP sweep is monkeypatched so the suite runs offline. We're asserting:
  - enumerate_hosts respects the MAX_HOSTS_PER_SCAN ceiling
  - ping_args builds the right flags per platform
  - scan_subnet filters ARP entries to the scanned subnet
  - Scanner auto-picks the first UP interface
  - Scanner raises when the requested interface isn't found
"""

from __future__ import annotations

import pytest

from findio import Device, ScanResult, Scanner
from findio import scanner as sc


# --------------------------------------------------------------------------- #
# Host enumeration                                                            #
# --------------------------------------------------------------------------- #


class TestEnumerateHosts:
    def test_slash_30(self):
        # /30 has 4 addresses, 2 usable hosts
        hosts = sc._enumerate_hosts("192.0.2.0/30")
        assert hosts == ("192.0.2.1", "192.0.2.2")

    def test_slash_24_host_count(self):
        hosts = sc._enumerate_hosts("198.51.100.0/24")
        assert len(hosts) == 254
        assert "198.51.100.1" in hosts
        assert "198.51.100.254" in hosts
        assert "198.51.100.0" not in hosts
        assert "198.51.100.255" not in hosts

    def test_rejects_oversized_subnet(self):
        # /20 = 4094 hosts, well over the 1024 cap
        with pytest.raises(ValueError, match="Refusing to sweep"):
            sc._enumerate_hosts("192.0.2.0/20")

    def test_strict_false_accepts_host_address(self):
        # 198.51.100.131/24 (a host address + prefix) should still enumerate /24
        hosts = sc._enumerate_hosts("198.51.100.131/24")
        assert len(hosts) == 254


# --------------------------------------------------------------------------- #
# Ping argument builder                                                       #
# --------------------------------------------------------------------------- #


class TestPingArgs:
    def test_macos_uses_milliseconds(self):
        args = sc._ping_args("192.0.2.1", 500, "darwin")
        assert args == ["ping", "-c", "1", "-n", "-q", "-W", "500", "192.0.2.1"]

    def test_linux_uses_seconds(self):
        # 500ms rounds up to 1 second on Linux
        args = sc._ping_args("192.0.2.1", 500, "linux")
        assert args == ["ping", "-c", "1", "-n", "-q", "-W", "1", "192.0.2.1"]

    def test_linux_rounds_up(self):
        args = sc._ping_args("192.0.2.1", 1500, "linux")
        assert args[-2] == "2"  # 1500ms → 2s (ceil)

    def test_linux_never_zero(self):
        args = sc._ping_args("192.0.2.1", 50, "linux")
        assert args[-2] == "1"


# --------------------------------------------------------------------------- #
# scan_subnet — monkey-patched, offline                                       #
# --------------------------------------------------------------------------- #


class TestScanSubnet:
    @pytest.fixture
    def patched(self, monkeypatch):
        """Skip real pings; inject a controlled ARP table."""
        sent: list[str] = []

        def fake_ping(ip, timeout_ms, plat):
            sent.append(ip)

        def fake_arp():
            return {
                "198.51.100.1":   ("00:00:5E:00:53:01", "en0"),
                "198.51.100.131": ("D0:11:E5:00:53:02", "en0"),
                "198.51.100.254": ("00:00:5E:00:53:03", "en0"),
                # outside the scanned /24 — must be filtered out
                "203.0.113.99":     ("AA:BB:CC:DD:EE:FF", "en9"),
            }

        monkeypatch.setattr(sc, "_ping", fake_ping)
        monkeypatch.setattr(sc._plat, "read_arp_table", fake_arp)
        return sent

    def test_returns_scanresult(self, patched):
        result = sc.scan_subnet("en0", "198.51.100.131/24", workers=4)
        assert isinstance(result, ScanResult)
        assert result.iface == "en0"
        assert result.cidr == "198.51.100.131/24"

    def test_filters_to_scanned_subnet(self, patched):
        result = sc.scan_subnet("en0", "198.51.100.131/24", workers=4)
        ips = {d.ip for d in result.devices}
        assert ips == {"198.51.100.1", "198.51.100.131", "198.51.100.254"}
        assert "203.0.113.99" not in ips

    def test_devices_are_sorted_numerically(self, patched):
        result = sc.scan_subnet("en0", "198.51.100.131/24", workers=4)
        ips = [d.ip for d in result.devices]
        assert ips == ["198.51.100.1", "198.51.100.131", "198.51.100.254"]

    def test_devices_have_mac_and_iface(self, patched):
        result = sc.scan_subnet("en0", "198.51.100.131/24", workers=4)
        d = next(x for x in result.devices if x.ip == "198.51.100.1")
        assert d.mac == "00:00:5E:00:53:01"
        assert d.iface == "en0"
        assert d.last_seen is not None
        assert isinstance(d, Device)

    def test_fires_a_ping_per_host(self, patched):
        sc.scan_subnet("en0", "198.51.100.0/30", workers=4)
        # /30 has 2 hosts
        assert len(patched) == 2
        assert set(patched) == {"198.51.100.1", "198.51.100.2"}


# --------------------------------------------------------------------------- #
# Scanner class                                                               #
# --------------------------------------------------------------------------- #


class TestScannerClass:
    @pytest.fixture
    def fake_env(self, monkeypatch):
        monkeypatch.setattr(sc, "_ping", lambda ip, t, p: None)
        monkeypatch.setattr(sc._plat, "read_arp_table", lambda: {})
        monkeypatch.setattr(
            sc._plat, "list_interfaces",
            lambda: (
                {"name": "en0", "ip": "198.51.100.131",
                 "cidr": "198.51.100.131/30", "is_up": True},
                {"name": "en5", "ip": "192.0.2.5",
                 "cidr": "192.0.2.5/30", "is_up": True},
            ),
        )

    def test_construct_without_args(self):
        s = Scanner()
        assert s.iface is None
        assert s.cidr is None

    def test_auto_picks_first_interface(self, fake_env):
        result = Scanner(workers=2).scan()
        assert result.iface == "en0"
        assert result.cidr == "198.51.100.131/30"

    def test_honors_explicit_interface(self, fake_env):
        result = Scanner(iface="en5", workers=2).scan()
        assert result.iface == "en5"
        assert result.cidr == "192.0.2.5/30"

    def test_honors_explicit_cidr_override(self, fake_env):
        result = Scanner(iface="en0", cidr="198.51.100.0/30", workers=2).scan()
        assert result.cidr == "198.51.100.0/30"

    def test_unknown_interface_raises(self, fake_env):
        with pytest.raises(RuntimeError, match="not found"):
            Scanner(iface="does-not-exist").scan()

    def test_no_interfaces_raises(self, monkeypatch):
        monkeypatch.setattr(sc._plat, "list_interfaces", lambda: ())
        with pytest.raises(RuntimeError, match="No scannable"):
            Scanner().scan()

    def test_scan_all_walks_every_iface(self, fake_env):
        results = Scanner(workers=2).scan_all()
        assert len(results) == 2
        assert {r.iface for r in results} == {"en0", "en5"}


# --------------------------------------------------------------------------- #
# Safety: public-range refusal + rate limiting                                #
# --------------------------------------------------------------------------- #


class TestSafetyLimits:
    def test_refuses_public_range_by_default(self):
        with pytest.raises(ValueError, match="authorized"):
            sc._enumerate_hosts("100.64.0.0/30")

    def test_allow_public_overrides(self):
        assert len(sc._enumerate_hosts("100.64.0.0/30", allow_public=True)) == 2

    def test_documentation_and_private_ranges_allowed(self):
        assert sc._enumerate_hosts("192.0.2.0/30")
        assert sc._enumerate_hosts("198.51.100.0/30")
        assert sc._enumerate_hosts("203.0.113.0/30")
        assert sc._enumerate_hosts("169.254.1.0/30")

    def test_rate_limit_paces_probe_starts(self, monkeypatch):
        monkeypatch.setattr(sc, "_ping", lambda *a, **k: None)
        monkeypatch.setattr(sc._plat, "read_arp_table", lambda: {})
        t0 = sc.time.monotonic()
        # /28 = 14 hosts at 100/s => at least ~0.13s of pacing
        sc.scan_subnet("en0", "192.0.2.0/28", workers=2, max_rate=100.0)
        assert sc.time.monotonic() - t0 >= 0.12

    def test_unlimited_rate_does_not_sleep_per_host(self, monkeypatch):
        monkeypatch.setattr(sc, "_ping", lambda *a, **k: None)
        monkeypatch.setattr(sc._plat, "read_arp_table", lambda: {})
        t0 = sc.time.monotonic()
        sc.scan_subnet("en0", "192.0.2.0/24", workers=8, max_rate=0)
        assert sc.time.monotonic() - t0 < 1.0

"""
Platform shim tests — pure parser tests against captured fixtures.

Fixtures under tests/fixtures/ are real captures (see fixtures/README.md).
These tests MUST run without network or subprocess — parser functions are pure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from findio import platform as p


FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# normalize_mac                                                               #
# --------------------------------------------------------------------------- #


class TestNormalizeMac:
    def test_canonical_uppercase(self):
        assert p.normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_pads_short_octets(self):
        # macOS drops leading zeros: `e:0:5e:0:53:f` → `0E:00:5E:00:53:0F`
        assert p.normalize_mac("e:0:5e:0:53:f") == "0E:00:5E:00:53:0F"
        assert p.normalize_mac("0:0:5e:0:53:4") == "00:00:5E:00:53:04"

    def test_rejects_broadcast(self):
        # ff's first octet has I/G bit set → multicast/broadcast, not an endpoint
        assert p.normalize_mac("ff:ff:ff:ff:ff:ff") is None

    def test_rejects_ipv4_multicast(self):
        # 01:00:5e:* — IPv4 multicast OUI. I/G bit set on 0x01.
        assert p.normalize_mac("01:00:5e:00:00:fb") is None
        assert p.normalize_mac("1:0:5e:0:0:fb") is None  # short-octet variant

    def test_rejects_malformed(self):
        assert p.normalize_mac("") is None
        assert p.normalize_mac("not-a-mac") is None
        assert p.normalize_mac("aa:bb:cc") is None  # too short
        assert p.normalize_mac("zz:bb:cc:dd:ee:ff") is None  # bad hex
        assert p.normalize_mac("(incomplete)") is None

    def test_accepts_locally_administered_unicast(self):
        # Random-MAC clients (iOS/Android privacy) set the locally-administered
        # bit (0x02) on the first octet but leave I/G clear. They're still real
        # endpoints we want to list. Example from the real capture:
        # 76:00:5e:00:53:05 — first octet 0x76 = 0111_0110, I/G clear, L/A set.
        assert p.normalize_mac("76:00:5e:00:53:05") == "76:00:5E:00:53:05"


# --------------------------------------------------------------------------- #
# macOS ARP parser — real captured fixture                                    #
# --------------------------------------------------------------------------- #


class TestParseMacosArp:
    @pytest.fixture
    def parsed(self) -> dict:
        text = (FIXTURES / "arp_macos_sample.txt").read_text()
        return p.parse_macos_arp(text)

    def test_parses_normal_row(self, parsed):
        assert parsed["198.51.100.1"] == ("00:00:5E:00:53:01", "en0")

    def test_parses_short_octet_mac(self, parsed):
        # 198.51.100.73 → e:0:5e:0:53:f → 0E:00:5E:00:53:0F
        assert parsed["198.51.100.73"] == ("0E:00:5E:00:53:0F", "en0")

    def test_parses_permanent_row(self, parsed):
        # "on en0 ifscope permanent [ethernet]" — must parse identically
        assert parsed["198.51.100.131"] == ("D0:11:E5:00:53:02", "en0")

    def test_skips_incomplete_row(self, parsed):
        # 198.51.100.162 is `(incomplete)`
        assert "198.51.100.162" not in parsed

    def test_skips_broadcast_row(self, parsed):
        # 198.51.100.255 → ff:ff:ff:ff:ff:ff — must drop
        assert "198.51.100.255" not in parsed

    def test_skips_multicast_row(self, parsed):
        # 224.0.0.251 → 1:0:5e:0:0:fb — must drop
        assert "224.0.0.251" not in parsed

    def test_expected_row_count(self, parsed):
        # Real fixture: 25 rows total, 1 incomplete + 1 broadcast + 1 multicast = 22 valid
        assert len(parsed) == 22

    def test_empty_input_is_empty_dict(self):
        assert p.parse_macos_arp("") == {}

    def test_unmatched_garbage_is_ignored(self):
        assert p.parse_macos_arp("totally not an arp line\nneither is this\n") == {}


# --------------------------------------------------------------------------- #
# Linux ARP parser — synthetic fixture (no Linux bench here)                  #
# --------------------------------------------------------------------------- #


class TestParseLinuxArp:
    @pytest.fixture
    def parsed(self) -> dict:
        text = (FIXTURES / "arp_linux_sample.txt").read_text()
        return p.parse_linux_arp(text)

    def test_accepts_reachable(self, parsed):
        assert parsed["192.0.2.1"] == ("AA:BB:CC:DD:EE:FF", "enp3s0")

    def test_accepts_stale(self, parsed):
        assert parsed["192.0.2.42"] == ("12:34:56:78:9A:BC", "enp3s0")

    def test_accepts_permanent(self, parsed):
        assert parsed["192.0.2.50"] == ("00:11:22:33:44:55", "enp3s0")

    def test_accepts_delay_and_probe(self, parsed):
        assert "192.0.2.99" in parsed  # DELAY
        assert "192.0.2.123" in parsed  # PROBE

    def test_accepts_noarp(self, parsed):
        # Mcast 01:00:5e:* is dropped by mac filter, so NOARP coverage is
        # asserted via a non-multicast NOARP row — build one inline.
        text = "192.0.2.200 dev enp3s0 lladdr 02:aa:bb:cc:dd:ee NOARP\n"
        out = p.parse_linux_arp(text)
        assert out["192.0.2.200"] == ("02:AA:BB:CC:DD:EE", "enp3s0")

    def test_skips_failed(self, parsed):
        assert "192.0.2.17" not in parsed

    def test_skips_incomplete(self, parsed):
        assert "169.254.0.1" not in parsed

    def test_skips_multicast(self, parsed):
        assert "224.0.0.251" not in parsed

    def test_multi_iface(self, parsed):
        # enp4s0 rows should land alongside enp3s0 rows
        assert parsed["203.0.113.1"] == ("DE:AD:BE:EF:00:01", "enp4s0")

    def test_empty_input_is_empty_dict(self):
        assert p.parse_linux_arp("") == {}


# --------------------------------------------------------------------------- #
# Interface enumeration — macOS ifconfig                                      #
# --------------------------------------------------------------------------- #


_SAMPLE_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 198.51.100.131 netmask 0xffffff00 broadcast 198.51.100.255
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 11:22:33:44:55:66
\tinet 192.0.2.5 netmask 0xffffff00 broadcast 192.0.2.255
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 203.0.113.64 --> 203.0.113.64 netmask 0xffffffff
awdl0: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1484
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
en9: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether 77:88:99:aa:bb:cc
"""


class TestParseMacosIfconfig:
    @pytest.fixture
    def parsed(self) -> tuple:
        return p.parse_macos_ifconfig(_SAMPLE_IFCONFIG)

    def test_includes_real_ethernet(self, parsed):
        names = {r["name"] for r in parsed}
        assert "en0" in names
        assert "en5" in names

    def test_emits_cidr(self, parsed):
        en0 = next(r for r in parsed if r["name"] == "en0")
        assert en0["ip"] == "198.51.100.131"
        assert en0["cidr"] == "198.51.100.131/24"
        assert en0["is_up"] is True

    def test_filters_loopback(self, parsed):
        names = {r["name"] for r in parsed}
        assert "lo0" not in names

    def test_filters_virtual_interfaces(self, parsed):
        names = {r["name"] for r in parsed}
        assert "utun0" not in names
        assert "awdl0" not in names
        assert "bridge0" not in names

    def test_filters_down_interfaces(self, parsed):
        # en9 lacks UP,RUNNING flags and has no inet — must be excluded
        names = {r["name"] for r in parsed}
        assert "en9" not in names

    def test_hex_netmask_conversion(self):
        assert p._hex_netmask_to_prefix("ffffff00") == 24
        assert p._hex_netmask_to_prefix("ffff0000") == 16
        assert p._hex_netmask_to_prefix("ffffffff") == 32


# --------------------------------------------------------------------------- #
# Interface enumeration — Linux ip -4 -o addr                                 #
# --------------------------------------------------------------------------- #


_SAMPLE_IP_ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
3: enp3s0    inet 192.0.2.5/24 brd 192.0.2.255 scope global dynamic enp3s0\\       valid_lft forever
4: enp4s0    inet 203.0.113.10/24 brd 203.0.113.255 scope global enp4s0\\       valid_lft forever
5: docker0    inet 203.0.113.17/16 brd 203.0.113.255 scope global docker0\\       valid_lft forever
6: br-abc    inet 203.0.113.18/16 brd 203.0.113.254 scope global br-abc\\       valid_lft forever
"""


class TestParseLinuxIpaddr:
    @pytest.fixture
    def parsed(self) -> tuple:
        return p.parse_linux_ipaddr(_SAMPLE_IP_ADDR)

    def test_includes_real_ethernet(self, parsed):
        names = {r["name"] for r in parsed}
        assert "enp3s0" in names
        assert "enp4s0" in names

    def test_cidr_format(self, parsed):
        enp3 = next(r for r in parsed if r["name"] == "enp3s0")
        assert enp3["cidr"] == "192.0.2.5/24"

    def test_filters_loopback(self, parsed):
        names = {r["name"] for r in parsed}
        assert "lo" not in names

    def test_filters_docker_and_bridge(self, parsed):
        names = {r["name"] for r in parsed}
        assert "docker0" not in names
        assert "br-abc" not in names


# --------------------------------------------------------------------------- #
# Virtual prefix predicate                                                    #
# --------------------------------------------------------------------------- #


class TestVirtualPrefix:
    @pytest.mark.parametrize(
        "name",
        ["lo0", "utun3", "awdl0", "llw0", "anpi0", "ap1", "bridge0",
         "gif0", "stf0", "docker0", "br-abc123", "vmnet8", "vnic0",
         "vboxnet0", "tun0", "tap0"],
    )
    def test_virtual_names_filtered(self, name):
        assert p._is_virtual_name(name) is True

    @pytest.mark.parametrize("name", ["en0", "en5", "enp3s0", "eth0", "eno1"])
    def test_physical_names_kept(self, name):
        assert p._is_virtual_name(name) is False

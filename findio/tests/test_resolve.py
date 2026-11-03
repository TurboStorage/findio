"""
Resolver tests — probes monkeypatched so no real network traffic.

Covers:
  - OUI table loader (curated rows + IEEE MA-L format + user override)
  - BMC banner classifier
  - resolve_many orchestrator ordering + preservation
  - grab_banner socket handling (via fake socket)
"""

from __future__ import annotations

import socket

import pytest

from findio import Device, resolve_many
from findio import resolve as r


# --------------------------------------------------------------------------- #
# OUI table                                                                   #
# --------------------------------------------------------------------------- #


class TestOUILookup:
    def setup_method(self):
        # Reset the memoized table between tests — user overrides need to reload.
        r._oui_table.cache_clear()

    def test_curated_rows_load(self):
        assert r.resolve_vendor("D0:11:E5:00:53:02") == "Apple"
        assert r.resolve_vendor("D0-11-E5-00-53-02") == "Apple"
        assert r.resolve_vendor("d011e5005302") == "Apple"

    def test_unknown_prefix_returns_none(self):
        assert r.resolve_vendor("00:00:00:00:00:00") is None

    def test_missing_mac_returns_none(self):
        assert r.resolve_vendor(None) is None
        assert r.resolve_vendor("") is None

    def test_malformed_mac_returns_none(self):
        assert r.resolve_vendor("zzzzzz") is None

    def test_user_override_wins(self, tmp_path, monkeypatch):
        oui = tmp_path / "oui.csv"
        oui.write_text("D011E5,CustomOverride\n")
        monkeypatch.setenv("FINDIO_STATE_DIR", str(tmp_path))
        r._oui_table.cache_clear()
        assert r.resolve_vendor("D0:11:E5:00:53:02") == "CustomOverride"

    def test_ieee_ma_l_format_parses(self, tmp_path, monkeypatch):
        # Simulate a dropped-in IEEE MA-L CSV — 4 columns per row.
        oui = tmp_path / "oui.csv"
        oui.write_text(
            "Registry,Assignment,Organization Name,Organization Address\n"
            "MA-L,AABBCC,Example Corp,123 Some St\n"
        )
        monkeypatch.setenv("FINDIO_STATE_DIR", str(tmp_path))
        r._oui_table.cache_clear()
        assert r.resolve_vendor("AA:BB:CC:00:00:01") == "Example Corp"

    def test_comments_ignored(self, tmp_path, monkeypatch):
        oui = tmp_path / "oui.csv"
        oui.write_text("# this is a comment\nABCDEF,Test Vendor\n")
        monkeypatch.setenv("FINDIO_STATE_DIR", str(tmp_path))
        r._oui_table.cache_clear()
        assert r.resolve_vendor("AB:CD:EF:00:00:00") == "Test Vendor"


# --------------------------------------------------------------------------- #
# BMC banner classifier                                                       #
# --------------------------------------------------------------------------- #


class TestClassifyBanner:
    @pytest.mark.parametrize("banner, expected", [
        ("SSH-2.0-OpenSSH_7.4-hpiLO-2.70", "HPE iLO"),
        ("SSH-2.0-mod_sshd", "HPE iLO"),
        ("SSH-2.0-OpenSSH_7.0 Dell iDRAC 9.00.00.00", "Dell iDRAC"),
        ("SSH-2.0-SMCsshd_2.3.3", "Supermicro BMC"),
        ("SSH-2.0-OpenSSH_8.4 OpenBMC", "OpenBMC"),
        ("SSH-2.0-OpenSSH_6.6.1 AMI-Megarac", "AMI Megarac"),
        ("SSH-2.0-dropbear_2019.78", "Dropbear SSH (embedded)"),
        ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", None),
        ("", None),
        (None, None),
    ])
    def test_classification(self, banner, expected):
        assert r.classify_banner(banner) == expected


# --------------------------------------------------------------------------- #
# grab_banner — socket mocked                                                 #
# --------------------------------------------------------------------------- #


class _FakeSocket:
    def __init__(self, data: bytes):
        self._data = data
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def settimeout(self, _): pass
    def recv(self, n): return self._data[:n]


class TestGrabBanner:
    def test_returns_first_line(self, monkeypatch):
        fake = _FakeSocket(b"SSH-2.0-OpenSSH_8.4\r\nmore stuff\n")
        monkeypatch.setattr(
            "findio.resolve.socket.create_connection", lambda *a, **kw: fake
        )
        assert r.grab_banner("192.0.2.1") == "SSH-2.0-OpenSSH_8.4"

    def test_empty_response_returns_none(self, monkeypatch):
        fake = _FakeSocket(b"")
        monkeypatch.setattr(
            "findio.resolve.socket.create_connection", lambda *a, **kw: fake
        )
        assert r.grab_banner("192.0.2.1") is None

    def test_connection_refused_returns_none(self, monkeypatch):
        def boom(*_a, **_kw):
            raise ConnectionRefusedError()
        monkeypatch.setattr("findio.resolve.socket.create_connection", boom)
        assert r.grab_banner("192.0.2.1") is None

    def test_timeout_returns_none(self, monkeypatch):
        def boom(*_a, **_kw):
            raise socket.timeout()
        monkeypatch.setattr("findio.resolve.socket.create_connection", boom)
        assert r.grab_banner("192.0.2.1") is None


# --------------------------------------------------------------------------- #
# resolve_hostname                                                            #
# --------------------------------------------------------------------------- #


class TestResolveHostname:
    def test_hit(self, monkeypatch):
        monkeypatch.setattr("findio.resolve._rdns_raw", lambda ip: "my-host.lan")
        assert r.resolve_hostname("192.0.2.1") == "my-host.lan"

    def test_miss(self, monkeypatch):
        monkeypatch.setattr("findio.resolve._rdns_raw", lambda ip: None)
        assert r.resolve_hostname("192.0.2.1") is None


# --------------------------------------------------------------------------- #
# resolve_many — orchestrator                                                 #
# --------------------------------------------------------------------------- #


class TestResolveMany:
    def test_preserves_order(self, monkeypatch):
        monkeypatch.setattr("findio.resolve.resolve_hostname", lambda ip, timeout_ms: f"h-{ip}")
        monkeypatch.setattr("findio.resolve.grab_banner", lambda ip, timeout_ms: None)
        devs = tuple(Device(ip=f"10.0.0.{i}", mac=f"AA:AA:AA:AA:AA:{i:02X}") for i in range(5))
        out = resolve_many(devs)
        assert [d.ip for d in out] == [d.ip for d in devs]
        assert [d.hostname for d in out] == [f"h-10.0.0.{i}" for i in range(5)]

    def test_empty_input(self):
        assert resolve_many(()) == ()

    def test_bmc_family_beats_oui_vendor(self, monkeypatch):
        monkeypatch.setattr("findio.resolve.resolve_hostname", lambda ip, timeout_ms: None)
        monkeypatch.setattr(
            "findio.resolve.grab_banner",
            lambda ip, timeout_ms: "SSH-2.0-OpenSSH_7.4-hpiLO-2.70",
        )
        # Even though the MAC has an OUI vendor ("Apple" in our curated list),
        # a BMC SSH banner hit should win — it's more specific.
        devs = (Device(ip="192.0.2.1", mac="D0:11:E5:AA:BB:CC"),)
        out = resolve_many(devs)
        assert out[0].vendor == "HPE iLO"
        assert out[0].notes and "hpiLO" in out[0].notes

    def test_probe_ssh_false_skips_banner(self, monkeypatch):
        called = {"banner": 0}

        def fake_banner(ip, timeout_ms):
            called["banner"] += 1
            return None

        monkeypatch.setattr("findio.resolve.resolve_hostname", lambda ip, timeout_ms: None)
        monkeypatch.setattr("findio.resolve.grab_banner", fake_banner)
        out = resolve_many(
            (Device(ip="192.0.2.1", mac="D0:11:E5:AA:BB:CC"),),
            probe_ssh=False,
        )
        assert called["banner"] == 0
        # OUI still applied
        assert out[0].vendor == "Apple"

    def test_keeps_existing_device_metadata(self, monkeypatch):
        monkeypatch.setattr("findio.resolve.resolve_hostname", lambda ip, timeout_ms: None)
        monkeypatch.setattr("findio.resolve.grab_banner", lambda ip, timeout_ms: None)
        d = Device(
            ip="192.0.2.1", mac="D0:11:E5:AA:BB:CC",
            label="laptop", is_test_system=True,
            first_seen="2026-01-01T00:00:00+00:00",
        )
        out = resolve_many((d,))[0]
        assert out.label == "laptop"
        assert out.is_test_system is True
        assert out.first_seen == "2026-01-01T00:00:00+00:00"
        # OUI still applied on top of existing fields
        assert out.vendor == "Apple"

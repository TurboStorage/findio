"""
CLI integration tests — drive `main(argv)` with mocked scanner, real registry.

The scanner is monkeypatched so tests run offline; the registry path is
isolated via --state-dir (equivalent of FINDIO_STATE_DIR).
"""

from __future__ import annotations

import json

import pytest

from findio import cli, scanner
from findio.models import Device, ScanResult


def _fake_scan_result(devices: tuple[Device, ...]) -> ScanResult:
    return ScanResult(
        iface="en0", cidr="192.0.2.0/30",
        started_at="2026-04-21T12:00:00+00:00",
        finished_at="2026-04-21T12:00:00+00:00",
        devices=devices,
    )


@pytest.fixture
def stub_scan(monkeypatch):
    """Phase-wide stub: Scanner.scan() returns whatever this fixture is set to."""
    state = {"devices": ()}

    def fake_scan(self):
        return _fake_scan_result(state["devices"])

    def fake_scan_all(self):
        return (_fake_scan_result(state["devices"]),)

    monkeypatch.setattr("findio.Scanner.scan", fake_scan)
    monkeypatch.setattr("findio.Scanner.scan_all", fake_scan_all)
    return state


# --------------------------------------------------------------------------- #
# version                                                                     #
# --------------------------------------------------------------------------- #


class TestVersion:
    def test_prints_version(self, capsys):
        rc = cli.main(["version"])
        assert rc == 0
        out = capsys.readouterr().out.strip()
        assert out.count(".") == 2  # semver


# --------------------------------------------------------------------------- #
# scan                                                                        #
# --------------------------------------------------------------------------- #


class TestScan:
    def test_plain_output_lists_devices(self, stub_scan, tmp_path, capsys):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        rc = cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "192.0.2.1" in out
        assert "AA:AA:AA:AA:AA:AA" in out
        assert "1 device(s)" in out

    def test_json_output_has_envelope(self, stub_scan, tmp_path, capsys):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        rc = cli.main(["--state-dir", str(tmp_path), "scan", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert "findio_api" in payload
        assert len(payload["scans"]) == 1
        assert payload["scans"][0]["devices"][0]["ip"] == "192.0.2.1"

    def test_empty_scan_returns_exit_3(self, stub_scan, tmp_path, capsys):
        stub_scan["devices"] = ()
        rc = cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        assert rc == 3

    def test_no_record_skips_registry(self, stub_scan, tmp_path):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        rc = cli.main(["--state-dir", str(tmp_path), "scan", "--plain", "--no-record"])
        assert rc == 0
        # state.db may exist (registry creation is lazy) but sightings must be empty.
        # Easiest check: reopen registry and confirm list_current is empty.
        from findio import DeviceRegistry
        with DeviceRegistry(state_dir=str(tmp_path)) as reg:
            assert reg.list_current() == ()

    def test_scan_records_to_registry(self, stub_scan, tmp_path):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        from findio import DeviceRegistry
        with DeviceRegistry(state_dir=str(tmp_path)) as reg:
            current = reg.list_current()
            assert len(current) == 1
            assert current[0].mac == "AA:AA:AA:AA:AA:AA"

    def test_scan_enriches_with_labels(self, stub_scan, tmp_path, capsys):
        # First scan: record device.
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        # Label it.
        cli.main(["--state-dir", str(tmp_path), "label",
                  "AA:AA:AA:AA:AA:AA", "bench-2"])
        capsys.readouterr()  # clear
        # Second scan: label should surface in output.
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        assert "bench-2" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# baseline                                                                    #
# --------------------------------------------------------------------------- #


class TestBaseline:
    def test_save_and_list(self, stub_scan, tmp_path, capsys):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        capsys.readouterr()
        assert cli.main(["--state-dir", str(tmp_path),
                         "baseline", "save", "pre-plug"]) == 0
        assert "pre-plug" in capsys.readouterr().out
        assert cli.main(["--state-dir", str(tmp_path),
                         "baseline", "list"]) == 0
        assert "pre-plug" in capsys.readouterr().out

    def test_list_empty_returns_3(self, tmp_path, capsys):
        rc = cli.main(["--state-dir", str(tmp_path), "baseline", "list"])
        assert rc == 3

    def test_drop_unknown_errors(self, tmp_path):
        rc = cli.main(["--state-dir", str(tmp_path),
                       "baseline", "drop", "nope"])
        assert rc == 2


# --------------------------------------------------------------------------- #
# label                                                                       #
# --------------------------------------------------------------------------- #


class TestLabel:
    def test_set_label(self, stub_scan, tmp_path, capsys):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        capsys.readouterr()
        rc = cli.main(["--state-dir", str(tmp_path), "label",
                       "AA:AA:AA:AA:AA:AA", "bench-2"])
        assert rc == 0
        assert "bench-2" in capsys.readouterr().out

    def test_set_label_unknown_mac_errors(self, tmp_path):
        rc = cli.main(["--state-dir", str(tmp_path), "label",
                       "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "nope"])
        assert rc == 2

    def test_clear_label(self, stub_scan, tmp_path):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        cli.main(["--state-dir", str(tmp_path), "label",
                  "AA:AA:AA:AA:AA:AA", "bench-2"])
        rc = cli.main(["--state-dir", str(tmp_path), "label",
                       "AA:AA:AA:AA:AA:AA", "--clear"])
        assert rc == 0


# --------------------------------------------------------------------------- #
# diff                                                                        #
# --------------------------------------------------------------------------- #


class TestDiff:
    def test_full_baseline_flow(self, stub_scan, tmp_path, capsys):
        # Scan 1: baseline devices.
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        cli.main(["--state-dir", str(tmp_path), "baseline", "save", "pre-plug"])
        capsys.readouterr()

        # Scan 2: AA moved, BB lost, CC appeared — the canonical plug-in flow.
        stub_scan["devices"] = (
            Device(ip="192.0.2.42", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T13:00:00+00:00"),
            Device(ip="192.0.2.77", mac="CC:CC:CC:CC:CC:CC",
                   last_seen="2026-04-21T13:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        capsys.readouterr()

        rc = cli.main(["--state-dir", str(tmp_path),
                       "diff", "--against", "pre-plug"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "NEW" in out
        assert "CC:CC:CC:CC:CC:CC" in out
        assert "CHANGED" in out
        assert "LOST" in out
        assert "BB:BB:BB:BB:BB:BB" in out

    def test_diff_json(self, stub_scan, tmp_path, capsys):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        cli.main(["--state-dir", str(tmp_path), "baseline", "save", "pre-plug"])
        stub_scan["devices"] = ()
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        capsys.readouterr()

        rc = cli.main(["--state-dir", str(tmp_path),
                       "diff", "--against", "pre-plug", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert "findio_api" in payload
        assert len(payload["diff"]["lost"]) == 1
        assert payload["diff"]["lost"][0]["mac"] == "AA:AA:AA:AA:AA:AA"

    def test_diff_unknown_baseline_errors(self, tmp_path):
        rc = cli.main(["--state-dir", str(tmp_path),
                       "diff", "--against", "nope"])
        assert rc == 2

    def test_diff_vs_last_scan_empty_single_scan(self, stub_scan, tmp_path, capsys):
        stub_scan["devices"] = (
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        cli.main(["--state-dir", str(tmp_path), "scan", "--plain"])
        capsys.readouterr()
        rc = cli.main(["--state-dir", str(tmp_path), "diff"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "new=0" in out


class TestSafetyFlags:
    def test_scan_refuses_public_cidr(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(
            scanner._plat, "list_interfaces",
            lambda: ({"name": "en0", "ip": "192.0.2.5",
                      "cidr": "192.0.2.5/24", "is_up": True},),
        )
        rc = cli.main(["--state-dir", str(tmp_path), "scan",
                       "--iface", "en0", "--cidr", "100.64.0.0/29", "--no-record"])
        assert rc == 2
        assert "authorized" in capsys.readouterr().err

    def test_scan_parser_exposes_rate_limit(self):
        args = cli._build_parser().parse_args(["scan", "--max-rate", "50"])
        assert args.max_rate == 50.0
        assert args.workers == 64
        assert args.allow_public is False

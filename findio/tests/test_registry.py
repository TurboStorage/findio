"""
DeviceRegistry tests — real SQLite files in tmp_path (no DB mocks).
"""

from __future__ import annotations


import pytest

from findio import Device, DeviceRegistry, ScanResult
from findio.registry import CURRENT_SCHEMA_VERSION


def _mk_scan(*devices: Device, iface: str = "en0", cidr: str = "192.0.2.0/24",
             started_at: str = "2026-04-21T12:00:00+00:00") -> ScanResult:
    return ScanResult(
        iface=iface,
        cidr=cidr,
        started_at=started_at,
        finished_at=started_at,
        devices=tuple(devices),
    )


@pytest.fixture
def reg(tmp_path):
    r = DeviceRegistry(state_dir=str(tmp_path))
    yield r
    r.close()


# --------------------------------------------------------------------------- #
# Setup / migrations                                                          #
# --------------------------------------------------------------------------- #


class TestSetup:
    def test_creates_state_dir(self, tmp_path):
        target = tmp_path / "nested" / "findio"
        r = DeviceRegistry(state_dir=str(target))
        assert target.exists()
        assert (target / "state.db").exists()
        r.close()

    def test_schema_version_set(self, reg):
        row = reg._conn.execute(
            "SELECT version FROM schema_meta"
        ).fetchone()
        assert row["version"] == CURRENT_SCHEMA_VERSION

    def test_reopening_is_idempotent(self, tmp_path):
        r1 = DeviceRegistry(state_dir=str(tmp_path))
        r1.close()
        r2 = DeviceRegistry(state_dir=str(tmp_path))
        row = r2._conn.execute(
            "SELECT version FROM schema_meta"
        ).fetchone()
        assert row["version"] == CURRENT_SCHEMA_VERSION
        r2.close()

    def test_env_var_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FINDIO_STATE_DIR", str(tmp_path / "via-env"))
        r = DeviceRegistry()
        assert (tmp_path / "via-env" / "state.db").exists()
        r.close()

    def test_argument_wins_over_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FINDIO_STATE_DIR", str(tmp_path / "should-not-use"))
        r = DeviceRegistry(state_dir=str(tmp_path / "explicit"))
        assert (tmp_path / "explicit" / "state.db").exists()
        assert not (tmp_path / "should-not-use").exists()
        r.close()


# --------------------------------------------------------------------------- #
# record_scan + list_current                                                  #
# --------------------------------------------------------------------------- #


class TestRecordScan:
    def test_inserts_devices_and_sightings(self, reg):
        scan = _mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        )
        scan_id = reg.record_scan(scan)
        assert scan_id >= 1

        devices = reg.list_current()
        assert {d.mac for d in devices} == {"AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"}
        assert all(d.first_seen for d in devices)

    def test_upserts_on_second_sighting(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
            started_at="2026-04-21T12:00:00+00:00",
        ))
        # second scan, same MAC, new IP
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.99", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T13:00:00+00:00"),
            started_at="2026-04-21T13:00:00+00:00",
        ))
        current = reg.list_current()
        assert len(current) == 1
        assert current[0].ip == "192.0.2.99"
        # first_seen preserved from original insert
        assert current[0].first_seen == "2026-04-21T12:00:00+00:00"

    def test_empty_scan_still_recorded(self, reg):
        reg.record_scan(_mk_scan())
        assert reg.list_current() == ()

    def test_list_current_empty_when_no_scans(self, reg):
        assert reg.list_current() == ()


# --------------------------------------------------------------------------- #
# Labels                                                                      #
# --------------------------------------------------------------------------- #


class TestLabels:
    def test_set_and_get_label(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.set_label("AA:AA:AA:AA:AA:AA", "bench-2")
        d = reg.get_by_label("bench-2")
        assert d is not None
        assert d.mac == "AA:AA:AA:AA:AA:AA"
        assert d.label == "bench-2"

    def test_label_collision_raises(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.set_label("AA:AA:AA:AA:AA:AA", "bench-2")
        with pytest.raises(ValueError, match="already assigned"):
            reg.set_label("BB:BB:BB:BB:BB:BB", "bench-2")

    def test_set_label_idempotent_on_same_mac(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.set_label("AA:AA:AA:AA:AA:AA", "bench-2")
        reg.set_label("AA:AA:AA:AA:AA:AA", "bench-2")  # must not raise

    def test_clear_label_frees_name(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.set_label("AA:AA:AA:AA:AA:AA", "bench-2")
        reg.clear_label("AA:AA:AA:AA:AA:AA")
        # label is now free
        reg.set_label("BB:BB:BB:BB:BB:BB", "bench-2")
        assert reg.get_by_label("bench-2").mac == "BB:BB:BB:BB:BB:BB"

    def test_set_label_on_unknown_mac_raises(self, reg):
        with pytest.raises(ValueError, match="not in registry"):
            reg.set_label("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "whatever")


# --------------------------------------------------------------------------- #
# Baselines + diffs                                                           #
# --------------------------------------------------------------------------- #


class TestBaselinesAndDiff:
    def test_save_baseline_requires_scan(self, reg):
        with pytest.raises(RuntimeError, match="No scans"):
            reg.save_baseline("pre-plug")

    def test_diff_against_baseline(self, reg):
        # Baseline: 2 devices
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB", iface="en0",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.save_baseline("pre-plug")

        # Post-plug: AA moves IP, BB lost, CC appears
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.42", mac="AA:AA:AA:AA:AA:AA", iface="en0",
                   last_seen="2026-04-21T13:00:00+00:00"),
            Device(ip="192.0.2.77", mac="CC:CC:CC:CC:CC:CC", iface="en0",
                   last_seen="2026-04-21T13:00:00+00:00"),
        ))

        diff = reg.diff_against_baseline("pre-plug")
        assert {d.mac for d in diff.new} == {"CC:CC:CC:CC:CC:CC"}
        assert {d.mac for d in diff.lost} == {"BB:BB:BB:BB:BB:BB"}
        assert len(diff.changed) == 1
        before, after = diff.changed[0]
        assert before.mac == "AA:AA:AA:AA:AA:AA"
        assert before.ip == "192.0.2.1"
        assert after.ip == "192.0.2.42"
        assert diff.unchanged == ()

    def test_diff_against_last_scan_empty_when_single_scan(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        diff = reg.diff_against_last_scan()
        assert diff.new == ()
        assert diff.lost == ()

    def test_diff_against_last_scan_two_snapshots(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
            started_at="2026-04-21T12:00:00+00:00",
        ))
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T13:00:00+00:00"),
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB",
                   last_seen="2026-04-21T13:00:00+00:00"),
            started_at="2026-04-21T13:00:00+00:00",
        ))
        diff = reg.diff_against_last_scan()
        assert {d.mac for d in diff.new} == {"BB:BB:BB:BB:BB:BB"}
        assert {d.mac for d in diff.unchanged} == {"AA:AA:AA:AA:AA:AA"}

    def test_save_baseline_replaces_existing(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.save_baseline("pre-plug")
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB",
                   last_seen="2026-04-21T13:00:00+00:00"),
        ))
        reg.save_baseline("pre-plug")  # overwrite

        # The only baseline member now should be BB
        diff = reg.diff_against_baseline("pre-plug")
        assert diff.lost == ()  # BB is in both
        assert diff.new == ()
        assert {d.mac for d in diff.unchanged} == {"BB:BB:BB:BB:BB:BB"}

    def test_list_and_drop_baselines(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.save_baseline("pre-plug")
        reg.save_baseline("clean-room")
        assert set(reg.list_baselines()) == {"pre-plug", "clean-room"}

        reg.drop_baseline("pre-plug")
        assert reg.list_baselines() == ("clean-room",)

        with pytest.raises(ValueError, match="does not exist"):
            reg.drop_baseline("nope")

    def test_diff_against_unknown_baseline_raises(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        with pytest.raises(ValueError, match="does not exist"):
            reg.diff_against_baseline("nope")


# --------------------------------------------------------------------------- #
# Test-system flag                                                            #
# --------------------------------------------------------------------------- #


class TestTestSystemFlag:
    def test_mark_and_filter(self, reg):
        reg.record_scan(_mk_scan(
            Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                   last_seen="2026-04-21T12:00:00+00:00"),
            Device(ip="192.0.2.2", mac="BB:BB:BB:BB:BB:BB",
                   last_seen="2026-04-21T12:00:00+00:00"),
        ))
        reg.mark_test_system("AA:AA:AA:AA:AA:AA")
        only = reg.list_current(test_systems_only=True)
        assert {d.mac for d in only} == {"AA:AA:AA:AA:AA:AA"}
        assert only[0].is_test_system is True


# --------------------------------------------------------------------------- #
# pick_by_label public-API smoke                                              #
# --------------------------------------------------------------------------- #


class TestPickByLabel:
    def test_known_label(self, tmp_path):
        from findio import pick_by_label
        with DeviceRegistry(state_dir=str(tmp_path)) as reg:
            reg.record_scan(_mk_scan(
                Device(ip="192.0.2.1", mac="AA:AA:AA:AA:AA:AA",
                       last_seen="2026-04-21T12:00:00+00:00"),
            ))
            reg.set_label("AA:AA:AA:AA:AA:AA", "bench-2")
        d = pick_by_label("bench-2", state_dir=str(tmp_path))
        assert d is not None
        assert d.mac == "AA:AA:AA:AA:AA:AA"

    def test_unknown_label(self, tmp_path):
        from findio import pick_by_label
        assert pick_by_label("nope", state_dir=str(tmp_path)) is None

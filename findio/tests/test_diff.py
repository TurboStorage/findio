"""
Diff engine tests — pure function, disjoint sets.
"""

from __future__ import annotations

from findio import Device
from findio.diff import compute_diff


def _d(mac: str, ip: str, **kw) -> Device:
    return Device(ip=ip, mac=mac, **kw)


class TestComputeDiff:
    def test_empty_empty_is_all_empty(self):
        diff = compute_diff((), ())
        assert diff.new == ()
        assert diff.changed == ()
        assert diff.lost == ()
        assert diff.unchanged == ()
        assert diff.returned == ()

    def test_all_new(self):
        curr = (_d("AA:AA:AA:AA:AA:AA", "192.0.2.1"),)
        diff = compute_diff((), curr)
        assert diff.new == curr
        assert diff.lost == ()
        assert diff.changed == ()
        assert diff.unchanged == ()

    def test_all_lost(self):
        prev = (_d("AA:AA:AA:AA:AA:AA", "192.0.2.1"),)
        diff = compute_diff(prev, ())
        assert diff.lost == prev
        assert diff.new == ()
        assert diff.changed == ()
        assert diff.unchanged == ()

    def test_unchanged_match_by_mac_and_ip(self):
        prev = (_d("AA:AA:AA:AA:AA:AA", "192.0.2.1"),)
        curr = (_d("AA:AA:AA:AA:AA:AA", "192.0.2.1"),)
        diff = compute_diff(prev, curr)
        assert diff.unchanged == curr
        assert diff.new == ()
        assert diff.lost == ()
        assert diff.changed == ()

    def test_changed_same_mac_new_ip(self):
        before = _d("AA:AA:AA:AA:AA:AA", "192.0.2.1")
        after = _d("AA:AA:AA:AA:AA:AA", "192.0.2.99")
        diff = compute_diff((before,), (after,))
        assert diff.changed == ((before, after),)
        assert diff.new == ()
        assert diff.lost == ()
        assert diff.unchanged == ()

    def test_mixed_buckets_are_disjoint(self):
        prev = (
            _d("AA:AA:AA:AA:AA:AA", "192.0.2.1"),  # stays same → unchanged
            _d("BB:BB:BB:BB:BB:BB", "192.0.2.2"),  # IP moves   → changed
            _d("CC:CC:CC:CC:CC:CC", "192.0.2.3"),  # disappears → lost
        )
        curr = (
            _d("AA:AA:AA:AA:AA:AA", "192.0.2.1"),  # unchanged
            _d("BB:BB:BB:BB:BB:BB", "192.0.2.55"),  # changed (IP moved)
            _d("DD:DD:DD:DD:DD:DD", "192.0.2.4"),  # new
        )
        diff = compute_diff(prev, curr)

        assert {d.mac for d in diff.new} == {"DD:DD:DD:DD:DD:DD"}
        assert {d.mac for d in diff.lost} == {"CC:CC:CC:CC:CC:CC"}
        assert {d.mac for d in diff.unchanged} == {"AA:AA:AA:AA:AA:AA"}
        assert len(diff.changed) == 1
        before, after = diff.changed[0]
        assert before.ip == "192.0.2.2"
        assert after.ip == "192.0.2.55"

    def test_ignores_devices_without_mac(self):
        # Phase 1 guarantees MACs, but the function should be defensive.
        prev = (Device(ip="192.0.2.1"),)
        curr = (Device(ip="192.0.2.1"),)
        diff = compute_diff(prev, curr)
        assert diff == compute_diff((), ())

    def test_results_are_sorted_by_mac(self):
        curr = (
            _d("FF:FF:FF:FF:FF:FE", "192.0.2.1"),
            _d("AA:AA:AA:AA:AA:AA", "192.0.2.2"),
            _d("CC:CC:CC:CC:CC:CC", "192.0.2.3"),
        )
        diff = compute_diff((), curr)
        assert [d.mac for d in diff.new] == [
            "AA:AA:AA:AA:AA:AA",
            "CC:CC:CC:CC:CC:CC",
            "FF:FF:FF:FF:FF:FE",
        ]

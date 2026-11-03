"""
Phase 4 TUI tests — headless via textual's Pilot harness.

Monkeypatches Scanner + resolve_many so no real network traffic happens.
Skipped cleanly if textual isn't available (matches ARCHITECTURE.md).

Covers:
  - app mounts and populates the DataTable from a scan
  - Enter on a row sets `app.chosen` to the matching Device
  - q exits with chosen = None
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual", reason="textual not installed")

from findio.models import Device, ScanResult
from findio.ui._app import FindIOPickerApp


_FAKE_DEVICES = (
    Device(ip="192.0.2.1", mac="AA:BB:CC:DD:EE:01", hostname="alpha", vendor="Apple"),
    Device(ip="192.0.2.2", mac="AA:BB:CC:DD:EE:02", hostname="bravo", vendor="Super Micro"),
    Device(ip="192.0.2.3", mac="AA:BB:CC:DD:EE:03", hostname="charlie"),
)


@pytest.fixture
def patched_scan(monkeypatch):
    """Stub Scanner.scan() + resolve_many + DeviceRegistry.get_by_mac."""
    result = ScanResult(
        iface="en0",
        cidr="192.0.2.0/24",
        started_at="2026-04-21T00:00:00+00:00",
        finished_at="2026-04-21T00:00:03+00:00",
        devices=_FAKE_DEVICES,
    )
    monkeypatch.setattr("findio.ui._app.Scanner.scan", lambda self: result)
    monkeypatch.setattr("findio.ui._app.resolve_many", lambda devs, **_kw: devs)

    class _NullReg:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def get_by_mac(self, _mac): return None
    monkeypatch.setattr("findio.ui._app.DeviceRegistry", lambda **_kw: _NullReg())
    return result


async def _wait_for_rows(app, n, *, pilot, attempts=50):
    from textual.widgets import DataTable
    for _ in range(attempts):
        if app.query_one(DataTable).row_count >= n:
            return
        await pilot.pause(0.02)


def test_app_populates_table(patched_scan):
    async def body():
        app = FindIOPickerApp(state_dir="/tmp")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _wait_for_rows(app, len(_FAKE_DEVICES), pilot=pilot)
            from textual.widgets import DataTable
            assert app.query_one(DataTable).row_count == len(_FAKE_DEVICES)
            assert app._devices == _FAKE_DEVICES
    asyncio.run(body())


def test_enter_picks_row(patched_scan):
    async def body():
        app = FindIOPickerApp(state_dir="/tmp")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _wait_for_rows(app, len(_FAKE_DEVICES), pilot=pilot)
            await pilot.press("enter")
            await pilot.pause()
        assert app.chosen is not None, "Enter should have picked row 0"
        assert app.chosen.mac == _FAKE_DEVICES[0].mac
    asyncio.run(body())


def test_q_cancels(patched_scan):
    async def body():
        app = FindIOPickerApp(state_dir="/tmp")
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
        assert app.chosen is None
    asyncio.run(body())


# --------------------------------------------------------------------------- #
# Pure-helper tests (no Textual runtime)                                      #
# --------------------------------------------------------------------------- #


def test_classify_row_new_lost_changed():
    from findio.diff import compute_diff
    from findio.ui._app import _classify_row, _STYLE_NEW, _STYLE_LOST, _STYLE_CHANGED, _STYLE_UNCHANGED

    baseline = (
        Device(ip="192.0.2.1", mac="AA:BB:CC:00:00:01"),
        Device(ip="192.0.2.2", mac="AA:BB:CC:00:00:02"),  # will be lost
    )
    current = (
        Device(ip="192.0.2.9", mac="AA:BB:CC:00:00:01"),  # CHANGED (new ip)
        Device(ip="192.0.2.3", mac="AA:BB:CC:00:00:03"),  # NEW
    )
    diff = compute_diff(baseline, current)

    # NEW row
    tag, style = _classify_row(current[1], diff)
    assert tag == "NEW" and style == _STYLE_NEW
    # CHANGED row
    tag, style = _classify_row(current[0], diff)
    assert tag == "CHG" and style == _STYLE_CHANGED
    # LOST row (as surfaced from baseline)
    tag, style = _classify_row(baseline[1], diff)
    assert tag == "LST" and style == _STYLE_LOST

    # diff=None path (watch off)
    tag, style = _classify_row(current[0], None)
    assert tag == "·" and style == _STYLE_UNCHANGED


def test_assemble_visible_appends_lost_to_bottom():
    from findio.ui._app import _assemble_visible

    baseline = (
        Device(ip="192.0.2.1", mac="AA:BB:CC:00:00:01"),
        Device(ip="192.0.2.2", mac="AA:BB:CC:00:00:02"),  # lost
    )
    current = (
        Device(ip="192.0.2.1", mac="AA:BB:CC:00:00:01"),
        Device(ip="192.0.2.3", mac="AA:BB:CC:00:00:03"),  # new
    )
    visible, diff = _assemble_visible(current, baseline)
    # Current rows first (preserved order), then the LOST row.
    assert [d.mac for d in visible] == [
        "AA:BB:CC:00:00:01",
        "AA:BB:CC:00:00:03",
        "AA:BB:CC:00:00:02",
    ]
    assert diff is not None
    assert len(diff.new) == 1 and len(diff.lost) == 1

    # Watch off → passthrough, no diff
    visible2, diff2 = _assemble_visible(current, None)
    assert visible2 == current
    assert diff2 is None


def test_make_row_uses_plain_text_no_emoji_expansion():
    """Cells wrap in rich.text.Text — `:cd:` in a MAC must not become 💿."""
    from findio.ui._app import _make_row

    d = Device(ip="192.0.2.1", mac="AA:CD:EE:FF:00:01", hostname="test:ab:host")
    row = _make_row(d, "·", "")
    # Text objects preserve literal content (plain attribute) without emoji sub.
    assert row[2].plain == "AA:CD:EE:FF:00:01"
    assert row[4].plain == "test:ab:host"
    # And no emoji characters snuck in (rough check — ASCII only in our inputs)
    assert all(c.isascii() for c in row[2].plain)
    assert all(c.isascii() for c in row[4].plain)


def test_ip_sort_key_numeric_order():
    """IPs must sort numerically, not lexicographically (192.0.2.2 < 192.0.2.10)."""
    from findio.ui._app import _ip_sort_key

    ips = ["192.0.2.10", "192.0.2.2", "192.0.2.1", "198.51.100.5", ""]
    sorted_ips = sorted(ips, key=_ip_sort_key)
    # Numeric order: 192.0.2.1 < 192.0.2.2 < 192.0.2.10 < 198.51.100.5, empty last.
    assert sorted_ips == ["192.0.2.1", "192.0.2.2", "192.0.2.10", "198.51.100.5", ""]


def test_sort_keys_all_columns_defined():
    """Every column in _COLUMN_DEFS must have a matching sort function."""
    from findio.ui._app import _COLUMN_DEFS, _SORT_KEYS

    for key, _label in _COLUMN_DEFS:
        assert key in _SORT_KEYS, f"column '{key}' has no sort function"


def test_sort_by_mac_and_hostname():
    """Verify MAC/hostname sort orders devices correctly (case-insensitive)."""
    from findio.ui._app import _SORT_KEYS

    devs = [
        Device(ip="192.0.2.3", mac="CC:CC:CC:00:00:03", hostname="Zulu"),
        Device(ip="192.0.2.1", mac="AA:AA:AA:00:00:01", hostname="alpha"),
        Device(ip="192.0.2.2", mac="BB:BB:BB:00:00:02", hostname="Bravo"),
    ]
    by_mac = sorted(devs, key=lambda d: _SORT_KEYS["mac"](d, "·"))
    assert [d.mac for d in by_mac] == [
        "AA:AA:AA:00:00:01", "BB:BB:BB:00:00:02", "CC:CC:CC:00:00:03",
    ]
    by_host = sorted(devs, key=lambda d: _SORT_KEYS["hostname"](d, "·"))
    # Case-insensitive: alpha, Bravo, Zulu.
    assert [d.hostname for d in by_host] == ["alpha", "Bravo", "Zulu"]


def test_sort_by_delta_floats_events_to_top():
    """Δ-sorted NEW/CHG/LST should rank ahead of unchanged rows."""
    from findio.ui._app import _SORT_KEYS

    d_new = Device(ip="192.0.2.5", mac="AA:00:00:00:00:05")
    d_chg = Device(ip="192.0.2.4", mac="AA:00:00:00:00:04")
    d_lst = Device(ip="192.0.2.3", mac="AA:00:00:00:00:03")
    d_unc = Device(ip="192.0.2.2", mac="AA:00:00:00:00:02")
    rows = [(d_unc, "·"), (d_lst, "LST"), (d_chg, "CHG"), (d_new, "NEW")]
    rows.sort(key=lambda r: _SORT_KEYS["delta"](r[0], r[1]))
    # Expected bucket order: NEW, CHG, LST, unchanged.
    assert [tag for _d, tag in rows] == ["NEW", "CHG", "LST", "·"]


def test_sort_state_labeled_first():
    """State sort: labeled > seen > new (fresh)."""
    from findio.ui._app import _SORT_KEYS

    fresh = Device(ip="192.0.2.1", mac="AA:00:00:00:00:01")  # no label, no first_seen → 'new'
    seen = Device(ip="192.0.2.2", mac="AA:00:00:00:00:02", first_seen="2026-04-01T00:00:00+00:00")
    lbld = Device(ip="192.0.2.3", mac="AA:00:00:00:00:03", label="bench-2")
    rows = [fresh, seen, lbld]
    rows.sort(key=lambda d: _SORT_KEYS["state"](d, "·"))
    assert rows[0] is lbld and rows[-1] is fresh


def test_header_click_toggles_sort_direction(patched_scan):
    """Clicking the same header twice toggles ascending ↔ descending."""
    async def body():
        app = FindIOPickerApp(state_dir="/tmp")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _wait_for_rows(app, len(_FAKE_DEVICES), pilot=pilot)

            # Simulate header click by invoking the handler with a stub event.
            class _Ev:
                class column_key:  # noqa: N801 - textual uses this shape
                    value = "mac"
            # First click on MAC: switch sort to mac ascending.
            app.on_data_table_header_selected(_Ev())
            assert app._sort_key == "mac"
            assert app._sort_desc is False
            # Second click: toggle to descending.
            app.on_data_table_header_selected(_Ev())
            assert app._sort_key == "mac"
            assert app._sort_desc is True
            # Click a different column: reset to ascending on new key.
            class _Ev2:
                class column_key:  # noqa: N801
                    value = "hostname"
            app.on_data_table_header_selected(_Ev2())
            assert app._sort_key == "hostname"
            assert app._sort_desc is False
    asyncio.run(body())


def test_every_column_header_is_clickable_and_sorts(patched_scan):
    """Contract: every column in _COLUMN_DEFS must sort when its header is clicked.

    The requirement is that ALL headers to sort — MAC/hostname/state were examples.
    This test prevents silent regressions where a column loses its sort fn or
    is skipped by the click handler.
    """
    from findio.ui._app import _COLUMN_DEFS

    async def body():
        app = FindIOPickerApp(state_dir="/tmp")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _wait_for_rows(app, len(_FAKE_DEVICES), pilot=pilot)

            # Use a sentinel starting column so the first click on each target
            # goes through the "switch to new column" branch (ascending).
            for col_key, _label in _COLUMN_DEFS:
                class _Ev:
                    class column_key:  # noqa: N801
                        pass
                _Ev.column_key.value = col_key  # type: ignore[attr-defined]

                # Park sort on a key that is never the target so the first
                # click always triggers the new-column branch.
                app._sort_key = "__none__"
                app._sort_desc = True  # also verifies desc gets reset on switch
                app.on_data_table_header_selected(_Ev())
                assert app._sort_key == col_key, f"clicking {col_key} did not activate sort"
                assert app._sort_desc is False, f"{col_key} first click must be ascending"

                # Second click → descending (same-column toggle).
                app.on_data_table_header_selected(_Ev())
                assert app._sort_desc is True, f"{col_key} second click must reverse"
    asyncio.run(body())


def test_status_bar_shows_sort_indicator(patched_scan):
    """Status line must include `sort: <col> ▲/▼` — bulletproof visual feedback."""
    async def body():
        app = FindIOPickerApp(state_dir="/tmp")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _wait_for_rows(app, len(_FAKE_DEVICES), pilot=pilot)
            status = app._last_status
            assert "sort:" in status
            assert "IP" in status  # default sort column
            assert "▲" in status  # default ascending
    asyncio.run(body())


def test_watch_arms_after_primary(patched_scan):
    """Press `w` before primary finishes → watch turns on, baseline set after primary."""
    async def body():
        app = FindIOPickerApp(state_dir="/tmp", watch_interval=60)
        async with app.run_test() as pilot:
            # Press w BEFORE primary completes — it should queue as latent.
            await pilot.press("w")
            # App may or may not have scanned yet; ensure we wait for scan.
            from textual.widgets import DataTable
            for _ in range(50):
                if app.query_one(DataTable).row_count >= len(_FAKE_DEVICES):
                    break
                await pilot.pause(0.02)
            # Give the post-populate _arm_watch a chance to run.
            await pilot.pause()
        assert app._primary_done is True
        assert app._watch_on is True
        assert app._watch_baseline is not None
        assert len(app._watch_baseline) == len(_FAKE_DEVICES)
    asyncio.run(body())

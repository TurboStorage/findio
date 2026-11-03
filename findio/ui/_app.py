"""
Textual App for the FindIO device picker.

Isolated from `tui.py` so the public entrypoint stays lazy — importing this
module requires textual/rich, which `tui.py` gates with `_lazy_import_textual`.

Features:
  - Live scan on mount; Enter picks, q cancels, r rescans.
  - Watch mode (w): after the primary scan completes, rescan on a timer and
    colour NEW / LOST / CHANGED rows relative to the watch-baseline (the scan
    that was visible when watch was armed). Press w again to disarm.
  - Watch-tick rescans skip resolve() for MACs already resolved — keeps ticks
    fast. New-to-us MACs get full resolution on their first sighting.
  - Rich cells are wrapped in plain Text() so MAC / hostname strings aren't
    interpreted as emoji shortcodes (`:cd:` → 💿, `:ab:` → 🆎, etc.).

State machine:
  _primary_done  flips True after the first scan completes. Watch mode cannot
                 run before this.
  _watch_on      toggled by `w`. When True and primary is done, we schedule
                 a repeating timer that fires _run_scan().
  _watch_baseline  snapshot taken when watch is armed. All diff highlighting
                   is relative to this (not relative to the previous tick).
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Static

from ..diff import compute_diff
from ..models import Device
from ..registry import DeviceRegistry
from ..resolve import resolve_many
from ..scanner import Scanner


# Default watch tick in seconds. A /24 sweep runs ~3s on macOS; anything
# below ~5s leaves almost no idle time between ticks.
DEFAULT_WATCH_INTERVAL = 10.0


# Row styles keyed by bucket name.
_STYLE_NEW = "bold #00d787"        # bright green
_STYLE_LOST = "dim strike #ff5f5f"  # red strike-through, dim
_STYLE_CHANGED = "bold #ffd75f"    # amber
_STYLE_UNCHANGED = ""              # default foreground


class FindIOPickerApp(App):
    """Picker + watch view. All keybinds listed in the footer."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #status {
        height: 1;
        padding: 0 1;
        background: $surface;
        color: $text-muted;
    }
    DataTable {
        height: 1fr;
    }
    DataTable > .datatable--cursor {
        background: $accent;
        color: $text;
    }
    """

    BINDINGS = (
        Binding("enter", "pick", "Pick", priority=True),
        Binding("r", "rescan", "Rescan"),
        Binding("w", "watch", "Watch"),
        Binding("q", "cancel", "Quit"),
        Binding("escape", "cancel", "Quit", show=False),
    )

    def __init__(
        self,
        state_dir: Optional[str] = None,
        watch_interval: float = DEFAULT_WATCH_INTERVAL,
    ) -> None:
        super().__init__()
        self._state_dir = state_dir
        self._watch_interval = watch_interval

        # Current visible set — union of (latest scan devices) + (LOST since baseline).
        self._devices: tuple[Device, ...] = ()
        # Most recent scan devices, unmerged with LOSTs. Used for diff.
        self._current_scan: tuple[Device, ...] = ()
        # MACs we've already done full resolution on (skip resolve on re-ticks).
        self._resolved_macs: set[str] = set()

        # Watch state.
        self._primary_done: bool = False
        self._watch_on: bool = False
        self._watch_baseline: Optional[tuple[Device, ...]] = None
        self._watch_timer: Optional[Timer] = None

        # Sort state. Default: IP ascending (matches scan-time ordering).
        self._sort_key: str = "ip"
        self._sort_desc: bool = False

        self.chosen: Optional[Device] = None
        self._last_status: str = ""

    # -- layout --------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("Scanning… (primary resolve can take several seconds)", id="status")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "FindIO — device picker"
        self.sub_title = "Enter: pick   r: rescan   w: watch   (click headers to sort)   q: quit"
        table = self.query_one(DataTable)
        # Column keys line up with _SORT_KEYS; click-to-sort maps on header_selected.
        for key, label in _COLUMN_DEFS:
            table.add_column(label, key=key)
        self._run_scan()

    def on_data_table_header_selected(self, event) -> None:  # type: ignore[no-untyped-def]
        """Click any column header → sort that column. Second click reverses.

        Robust key extraction: textual versions differ on whether `column_key`
        exposes `.value` or stringifies directly. Fall back to both.
        """
        ck = getattr(event, "column_key", None)
        col_key = getattr(ck, "value", None) if ck is not None else None
        if col_key is None and ck is not None:
            col_key = str(ck)
        if not col_key or col_key not in _SORT_KEYS:
            return
        if self._sort_key == col_key:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_key = col_key
            self._sort_desc = False
        self._refresh_table()

    # -- actions -------------------------------------------------------------

    def action_pick(self) -> None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        mac = row_key.value
        match = next((d for d in self._devices if d.mac == mac), None)
        if match is not None:
            self.chosen = match
            self.exit()

    def action_cancel(self) -> None:
        self.chosen = None
        self.exit()

    def action_rescan(self) -> None:
        self._run_scan()

    def action_watch(self) -> None:
        """Toggle watch mode. Baseline freezes at the moment watch is armed."""
        if self._watch_on:
            self._disarm_watch()
        else:
            if not self._primary_done:
                self._set_status("Primary scan still running — watch will arm when it finishes.")
                self._watch_on = True  # latent — on completion we'll wire the timer
                return
            self._arm_watch()

    # -- watch helpers -------------------------------------------------------

    def _arm_watch(self) -> None:
        """Freeze baseline + start rescan timer. Requires primary to be done."""
        self._watch_on = True
        self._watch_baseline = self._current_scan
        if self._watch_timer is not None:
            self._watch_timer.stop()
        self._watch_timer = self.set_interval(self._watch_interval, self._run_scan)
        self._refresh_table()  # re-render with watch-relative colouring
        self._update_status(f"watch ARMED — baseline locked, next tick in {self._watch_interval:.0f}s.")

    def _disarm_watch(self) -> None:
        self._watch_on = False
        self._watch_baseline = None
        if self._watch_timer is not None:
            self._watch_timer.stop()
            self._watch_timer = None
        self._refresh_table()
        self._update_status("watch disarmed.")

    # -- data pipeline -------------------------------------------------------

    def _run_scan(self) -> None:
        self.query_one(DataTable).loading = True
        if not self._primary_done:
            self._set_status("Scanning (primary)… resolving hostnames + banners…")
        else:
            self._set_status("Scanning…")
        # Snapshot which MACs are already resolved (thread-safe copy).
        already_resolved = frozenset(self._resolved_macs)
        self.run_worker(
            lambda: self._scan_and_enrich(already_resolved),
            thread=True,
            exclusive=True,
        )

    def _scan_and_enrich(self, already_resolved: frozenset) -> None:
        """Worker thread: sweep + selective resolve + registry merge."""
        try:
            scan = Scanner().scan()
            devices = scan.devices

            if not self._primary_done:
                # Primary: full resolve on everybody.
                devices = resolve_many(devices)
                fresh_macs = {d.mac for d in devices if d.mac}
            else:
                # Tick: resolve only unknowns; pass the rest through untouched.
                new_devs = tuple(d for d in devices if d.mac not in already_resolved)
                old_devs = tuple(d for d in devices if d.mac in already_resolved)
                resolved_new = resolve_many(new_devs) if new_devs else ()
                # Preserve original scan order.
                resolved_by_mac = {d.mac: d for d in resolved_new}
                devices = tuple(
                    resolved_by_mac.get(d.mac, d) for d in devices
                )
                fresh_macs = {d.mac for d in resolved_new if d.mac}

            with DeviceRegistry(state_dir=self._state_dir) as reg:
                stored = {d.mac: reg.get_by_mac(d.mac) for d in devices if d.mac}
            merged = tuple(_merge_registry(d, stored.get(d.mac)) for d in devices)
        except Exception as e:  # noqa: BLE001
            self.call_from_thread(self._fail, str(e))
            return
        self.call_from_thread(self._populate, merged, fresh_macs)

    def _fail(self, msg: str) -> None:
        self.query_one(DataTable).loading = False
        self._set_status(f"Scan failed: {msg}")

    def _populate(self, devices: tuple[Device, ...], fresh_resolved_macs: set) -> None:
        self._current_scan = devices
        self._resolved_macs.update(m for m in fresh_resolved_macs if m)

        was_primary = not self._primary_done
        if was_primary:
            self._primary_done = True
            # If user armed watch early, wire the timer now.
            if self._watch_on and self._watch_baseline is None:
                self._arm_watch()
                return  # _arm_watch calls _refresh_table already

        self._refresh_table()

    def _refresh_table(self) -> None:
        """Render the table from current scan + watch-baseline diff, with sort applied."""
        baseline = self._watch_baseline if self._watch_on else None
        visible, diff = _assemble_visible(self._current_scan, baseline)

        # Tag each device with its classification so sort can use it too.
        tagged = [(d, *_classify_row(d, diff)) for d in visible]
        sort_fn = _SORT_KEYS.get(self._sort_key, _SORT_KEYS["ip"])
        tagged.sort(key=lambda row: sort_fn(row[0], row[1]), reverse=self._sort_desc)

        self._devices = tuple(d for d, _tag, _style in tagged)

        table = self.query_one(DataTable)
        table.clear()
        for d, tag, style in tagged:
            row = _make_row(d, tag, style)
            table.add_row(*row, key=d.mac or d.ip)
        # Best-effort: update column labels with an arrow. Some Textual versions
        # cache header rendering — we also surface the active sort in the status
        # line below (which always repaints) so the user gets visible feedback
        # regardless of header-repaint behaviour.
        _set_sort_indicators(table, self._sort_key, self._sort_desc)
        table.loading = False
        if table.row_count:
            table.focus()

        self._update_status()

    def _update_status(self, prefix: str = "") -> None:
        parts = []
        if prefix:
            parts.append(prefix)
        if self._watch_on and self._primary_done and self._watch_baseline is not None:
            diff = compute_diff(self._watch_baseline, self._current_scan)
            parts.append(
                f"watch ON • interval {self._watch_interval:.0f}s • "
                f"+{len(diff.new)} new / -{len(diff.lost)} lost / ~{len(diff.changed)} chg"
            )
        elif self._watch_on and not self._primary_done:
            parts.append("watch armed — waiting for primary to finish")
        else:
            parts.append(f"{len(self._current_scan)} device(s) • press w to watch")
        # Sort indicator — bulletproof visual feedback regardless of header repaint.
        arrow = "▼" if self._sort_desc else "▲"
        sort_label = _COLUMN_LABELS.get(self._sort_key, self._sort_key)
        parts.append(f"sort: {sort_label} {arrow}")
        self._set_status("  •  ".join(parts))

    def _set_status(self, text: str) -> None:
        self._last_status = text
        self.query_one("#status", Static).update(text)


# --------------------------------------------------------------------------- #
# Pure helpers (no Textual state) — easy to unit-test                         #
# --------------------------------------------------------------------------- #


def _merge_registry(live: Device, stored: Optional[Device]) -> Device:
    """Overlay registry-only fields (label, ssh_user, is_test_system) on live."""
    if stored is None:
        return live
    return Device(
        ip=live.ip,
        mac=live.mac,
        iface=live.iface,
        label=live.label or stored.label,
        hostname=live.hostname or stored.hostname,
        vendor=live.vendor or stored.vendor,
        ssh_user=live.ssh_user or stored.ssh_user,
        ssh_port=live.ssh_port or stored.ssh_port,
        notes=live.notes or stored.notes,
        is_test_system=live.is_test_system or stored.is_test_system,
        first_seen=stored.first_seen or live.first_seen,
        last_seen=live.last_seen,
    )


def _assemble_visible(
    current: tuple[Device, ...],
    baseline: Optional[tuple[Device, ...]],
) -> tuple[tuple[Device, ...], object]:
    """Merge current scan + LOST devices from baseline into one ordered list.

    Returns (visible_devices, diff_or_none). When baseline is None, no diff is
    computed and visible == current.
    """
    if baseline is None:
        return current, None
    diff = compute_diff(baseline, current)
    # Order: current scan order first, then LOST rows pinned to the bottom.
    present_macs = {d.mac for d in current if d.mac}
    lost_tail = tuple(d for d in diff.lost if d.mac not in present_macs)
    return current + lost_tail, diff


def _classify_row(d: Device, diff) -> tuple[str, str]:
    """Return (tag, rich_style) for a given device relative to the diff.

    Tags are short 3-char markers suitable for the Δ column: NEW / LST / CHG / —.
    """
    if diff is None:
        return "·", _STYLE_UNCHANGED
    if any(x.mac and x.mac == d.mac for x in diff.new):
        return "NEW", _STYLE_NEW
    if any(x.mac and x.mac == d.mac for x in diff.lost):
        return "LST", _STYLE_LOST
    # diff.changed is tuple[(before, after), ...]; match on `after` (current row).
    if any(after.mac and after.mac == d.mac for _before, after in diff.changed):
        return "CHG", _STYLE_CHANGED
    return "·", _STYLE_UNCHANGED


def _make_row(d: Device, tag: str, style: str) -> tuple[Text, ...]:
    """Build Text cells. Wrapping in Text() disables rich emoji shortcodes
    (which otherwise turn MAC `:CD:` into 💿, `:AB:` into 🆎, etc.)."""
    fields = (
        tag,
        d.ip or "",
        d.mac or "",
        d.label or "",
        d.hostname or "",
        d.vendor or "",
        _state_badge(d),
    )
    return tuple(Text(v, style=style, no_wrap=True) for v in fields)


# Small badges for the State column — label wins, then first_seen recency.
_STATE_FRESH = "new"
_STATE_KNOWN = "seen"
_STATE_LABEL = "labeled"


def _state_badge(d: Device) -> str:
    if d.label:
        return _STATE_LABEL
    if d.first_seen is None:
        return _STATE_FRESH
    return _STATE_KNOWN


# --------------------------------------------------------------------------- #
# Column definitions + sort keys                                              #
# --------------------------------------------------------------------------- #


# (column-key, header-label). Column-key string is what headers emit on click.
_COLUMN_DEFS = (
    ("delta", "Δ"),
    ("ip", "IP"),
    ("mac", "MAC"),
    ("label", "Label"),
    ("hostname", "Hostname"),
    ("vendor", "Vendor"),
    ("state", "State"),
)

# Quick lookup for status-bar sort indicator.
_COLUMN_LABELS = {k: lbl for k, lbl in _COLUMN_DEFS}


# Δ ordering: NEW first, then CHG, LST, and unchanged last — so watch events
# float to the top of the table when sorting on that column.
_DELTA_RANK = {"NEW": 0, "CHG": 1, "LST": 2, "·": 3}

# State column ordering: labeled first (your gear), then seen, then new.
_STATE_RANK = {_STATE_LABEL: 0, _STATE_KNOWN: 1, _STATE_FRESH: 2}


def _ip_sort_key(s: str) -> tuple:
    """Numeric IP sort — empty strings sort last, invalid strings fall back to text."""
    if not s:
        return (1, ())  # empties to bottom in asc
    try:
        return (0, ipaddress.ip_address(s).packed)
    except ValueError:
        return (0, s.encode())


def _text_key(s: Optional[str]) -> tuple:
    """Generic text sort — empties to bottom, case-insensitive."""
    if not s:
        return (1, "")
    return (0, s.lower())


_SORT_KEYS: dict[str, Callable[[Device, str], tuple]] = {
    "delta": lambda d, tag: (_DELTA_RANK.get(tag, 99), _ip_sort_key(d.ip or "")),
    "ip": lambda d, _tag: _ip_sort_key(d.ip or ""),
    "mac": lambda d, _tag: _text_key(d.mac),
    "label": lambda d, _tag: _text_key(d.label),
    "hostname": lambda d, _tag: _text_key(d.hostname),
    "vendor": lambda d, _tag: _text_key(d.vendor),
    "state": lambda d, _tag: (_STATE_RANK.get(_state_badge(d), 99), _text_key(d.label)),
}


def _set_sort_indicators(table: "DataTable", active_key: str, desc: bool) -> None:
    """Rewrite column labels with a ▲/▼ arrow next to the active column.

    Best-effort: Textual caches header rendering, so label mutation alone may
    not repaint. We try multiple force-redraw paths. The authoritative sort
    indicator lives in the status bar (always repaints) — this is icing.
    """
    arrow = "▼" if desc else "▲"
    mutated = False
    for key, label in _COLUMN_DEFS:
        suffix = f" {arrow}" if key == active_key else ""
        try:
            column = table.columns[key]  # type: ignore[index]
        except (KeyError, AttributeError):
            continue
        column.label = Text(label + suffix, no_wrap=True)
        mutated = True
    if not mutated:
        return
    # Force a full re-layout so the new header labels actually paint.
    for method_name in ("_update_dimensions", "_clear_caches"):
        fn = getattr(table, method_name, None)
        if fn is None:
            continue
        try:
            # _update_dimensions takes an update_count argument in some versions.
            fn()
        except TypeError:
            try:
                fn(getattr(table, "_update_count", 0))
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass
    try:
        table.refresh(layout=True)
    except TypeError:
        try:
            table.refresh()
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        pass

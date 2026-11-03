"""
Diff engine.

Diff categories (keyed on MAC — Phase 1 guarantees every scan row has one):
  NEW        — MAC not in `previous`
  LOST       — MAC in `previous` but not in `current`
  CHANGED    — MAC in both; IP differs → (before, after) pair
  UNCHANGED  — MAC in both; IP matches
  RETURNED   — (Phase 6) requires history beyond two snapshots; stays empty here

These sets are disjoint by construction — every MAC lands in exactly one bucket.

`compute_diff` is a pure function — no I/O, no DB. Tests are trivial.
"""

from __future__ import annotations

from .models import Device, Diff


def compute_diff(
    previous: tuple[Device, ...],
    current: tuple[Device, ...],
) -> Diff:
    """Pure category assignment. MAC-keyed; devices without MACs are ignored."""
    prev_by_mac = {d.mac: d for d in previous if d.mac}
    curr_by_mac = {d.mac: d for d in current if d.mac}

    prev_macs = set(prev_by_mac)
    curr_macs = set(curr_by_mac)

    new = tuple(curr_by_mac[m] for m in sorted(curr_macs - prev_macs))
    lost = tuple(prev_by_mac[m] for m in sorted(prev_macs - curr_macs))

    changed: list[tuple[Device, Device]] = []
    unchanged: list[Device] = []
    for mac in sorted(prev_macs & curr_macs):
        before = prev_by_mac[mac]
        after = curr_by_mac[mac]
        if before.ip != after.ip:
            changed.append((before, after))
        else:
            unchanged.append(after)

    return Diff(
        new=new,
        changed=tuple(changed),
        lost=lost,
        returned=(),  # Phase 6: needs sightings history beyond two snapshots
        unchanged=tuple(unchanged),
    )

"""
CLI - argparse front-end. Dispatches to scanner / registry.

Commands (see ARCHITECTURE.md for full JSON schema + exit codes):
  findio scan     [--iface X] [--cidr X] [--all] [--plain] [--json] [--no-record]
  findio baseline save NAME [--notes TEXT]
  findio baseline list
  findio baseline drop NAME
  findio label    MAC LABEL
  findio label    --clear MAC
  findio diff     [--against NAME] [--json]
  findio version

  findio pick     [--label NAME] [--json]

Exit codes (STABLE - breaking change bumps FINDIO_API_VERSION MAJOR):
  0  success
  1  user cancelled (TUI quit, no selection)
  2  error (scan failure, bad args, DB corruption)
  3  no devices found / label not matched
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

import time

from . import FINDIO_API_VERSION, DeviceRegistry, Scanner, resolve_many
from .diff import compute_diff
from .models import Device, Diff, ScanResult


# --------------------------------------------------------------------------- #
# Output helpers                                                              #
# --------------------------------------------------------------------------- #


_AUTHORIZATION_NOTICE = (
    "findio: scanning sends ICMP echo (and an optional TCP/22 banner read) to "
    "every host in the subnet. Only scan networks you are authorized to use."
)


def _print_plain_scan(result: ScanResult) -> None:
    print(f"# {result.iface} {result.cidr}  "
          f"{result.started_at} -> {result.finished_at}")
    if not result.devices:
        print("(no devices)")
        return
    header = f"{'IP':<16} {'MAC':<18} {'LABEL':<14} {'HOSTNAME':<24} {'VENDOR':<24}"
    print(header)
    print("-" * len(header))
    for d in result.devices:
        hostname = (d.hostname or "")[:24]
        vendor = (d.vendor or "")[:24]
        label = (d.label or "")[:14]
        print(f"{d.ip:<16} {d.mac or '':<18} {label:<14} "
              f"{hostname:<24} {vendor:<24}")
    print(f"# {len(result.devices)} device(s)")


def _print_json_scans(results: tuple[ScanResult, ...]) -> None:
    payload = {
        "findio_api": FINDIO_API_VERSION,
        "scans": [
            {
                "iface": r.iface,
                "cidr": r.cidr,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "devices": [d.to_dict() for d in r.devices],
            }
            for r in results
        ],
    }
    print(json.dumps(payload, indent=2))


def _print_plain_diff(diff: Diff, heading: str) -> None:
    print(f"# {heading}")

    def _row(tag: str, d: Device, extra: str = "") -> str:
        label = f" {d.label}" if d.label else ""
        return f"  {tag:<10} {d.ip:<16} {d.mac or '':<18}{label}{extra}"

    if diff.new:
        for d in diff.new:
            print(_row("NEW", d))
    if diff.changed:
        for before, after in diff.changed:
            print(_row("CHANGED", after, f"  (was {before.ip})"))
    if diff.lost:
        for d in diff.lost:
            print(_row("LOST", d))
    if diff.returned:
        for d in diff.returned:
            print(_row("RETURNED", d))

    counts = (
        f"# new={len(diff.new)} changed={len(diff.changed)} "
        f"lost={len(diff.lost)} returned={len(diff.returned)} "
        f"unchanged={len(diff.unchanged)}"
    )
    print(counts)


def _print_json_diff(diff: Diff) -> None:
    payload = {
        "findio_api": FINDIO_API_VERSION,
        "diff": {
            "new": [d.to_dict() for d in diff.new],
            "changed": [
                {"before": b.to_dict(), "after": a.to_dict()}
                for b, a in diff.changed
            ],
            "lost": [d.to_dict() for d in diff.lost],
            "returned": [d.to_dict() for d in diff.returned],
            "unchanged": [d.to_dict() for d in diff.unchanged],
        },
    }
    print(json.dumps(payload, indent=2))


# --------------------------------------------------------------------------- #
# scan                                                                        #
# --------------------------------------------------------------------------- #


def _cmd_scan(args: argparse.Namespace) -> int:
    if getattr(args, "watch", False):
        return _cmd_scan_watch(args)
    try:
        results = _do_one_scan(args, resolve_unknowns_only=False)
    except (RuntimeError, ValueError) as e:
        print(f"findio: {e}", file=sys.stderr)
        return 2
    except _RegistryError as e:
        print(f"findio: registry write failed: {e}", file=sys.stderr)
        return 2

    if args.json:
        _print_json_scans(results)
    else:
        for r in results:
            _print_plain_scan(r)

    total = sum(len(r.devices) for r in results)
    return 0 if total > 0 else 3


class _RegistryError(RuntimeError):
    """Internal: bubbles registry failures out of _do_one_scan with context."""


def _do_one_scan(
    args: argparse.Namespace,
    *,
    resolve_unknowns_only: bool = False,
    already_resolved: Optional[set] = None,
) -> tuple[ScanResult, ...]:
    """Shared scan pipeline. Used by both `scan` one-shot and `scan --watch`.

    `resolve_unknowns_only` + `already_resolved` let watch-mode skip the slow
    probes for MACs whose hostname/vendor was resolved on a previous tick -
    resolve cost is a primary-scan tax only.
    """
    scanner = Scanner(
        iface=args.iface, cidr=args.cidr,
        timeout_ms=args.timeout_ms, workers=args.workers,
        max_rate=args.max_rate, allow_public=args.allow_public,
    )
    results = scanner.scan_all() if args.all else (scanner.scan(),)

    # Layer 1: name resolution.
    if args.resolve:
        enriched = []
        known = already_resolved or set()
        for r in results:
            if resolve_unknowns_only:
                to_resolve = tuple(d for d in r.devices if d.mac not in known)
                resolved = resolve_many(
                    to_resolve,
                    timeout_ms=args.resolve_timeout_ms,
                    workers=args.resolve_workers,
                    probe_ssh=not args.no_ssh_probe,
                ) if to_resolve else ()
                by_mac = {d.mac: d for d in resolved if d.mac}
                devs = tuple(by_mac.get(d.mac, d) for d in r.devices)
            else:
                devs = resolve_many(
                    r.devices,
                    timeout_ms=args.resolve_timeout_ms,
                    workers=args.resolve_workers,
                    probe_ssh=not args.no_ssh_probe,
                )
            enriched.append(ScanResult(
                iface=r.iface, cidr=r.cidr,
                started_at=r.started_at, finished_at=r.finished_at,
                devices=devs,
            ))
        results = tuple(enriched)

    # Layer 2: persist.
    if not args.no_record:
        try:
            with DeviceRegistry(state_dir=args.state_dir) as reg:
                for r in results:
                    reg.record_scan(r)
        except Exception as e:  # noqa: BLE001
            raise _RegistryError(str(e)) from e

    # Layer 3: enrich with registry metadata.
    if not args.no_record:
        with DeviceRegistry(state_dir=args.state_dir) as reg:
            results = tuple(
                ScanResult(
                    iface=r.iface, cidr=r.cidr,
                    started_at=r.started_at, finished_at=r.finished_at,
                    devices=_enrich_devices(reg, r.devices),
                )
                for r in results
            )

    return results


def _cmd_scan_watch(args: argparse.Namespace) -> int:
    """Watch loop: print primary scan, then on each interval print only deltas.

    Primary scan runs full resolution so hostnames + vendors land. Subsequent
    ticks skip resolve for MACs already enriched - keeps ticks fast.
    Ctrl-C exits with 0.
    """
    interval = max(2.0, float(args.interval))
    print(f"# watch mode - interval {interval:.0f}s - Ctrl-C to exit")
    try:
        primary = _do_one_scan(args, resolve_unknowns_only=False)
    except (RuntimeError, ValueError) as e:
        print(f"findio: {e}", file=sys.stderr)
        return 2

    # Flatten first scan's devices across all ifaces for diffing.
    def _flat(results: tuple[ScanResult, ...]) -> tuple[Device, ...]:
        out = []
        for r in results:
            out.extend(r.devices)
        return tuple(out)

    last = _flat(primary)
    resolved = {d.mac for d in last if d.mac}
    print(f"# primary: {len(last)} device(s). Watching for changes since {primary[0].finished_at}.")
    # Print the baseline roster too (so operator sees starting state).
    for r in primary:
        _print_plain_scan(r)

    try:
        while True:
            time.sleep(interval)
            try:
                tick = _do_one_scan(
                    args,
                    resolve_unknowns_only=True,
                    already_resolved=resolved,
                )
            except (RuntimeError, ValueError, _RegistryError) as e:
                print(f"# tick failed: {e}", file=sys.stderr)
                continue
            current = _flat(tick)
            diff = compute_diff(last, current)
            _print_watch_delta(diff, ts=tick[0].finished_at)
            resolved.update(d.mac for d in current if d.mac)
            last = current
    except KeyboardInterrupt:
        print("\n# watch stopped.")
        return 0


def _print_watch_delta(diff: Diff, ts: str) -> None:
    changes = len(diff.new) + len(diff.lost) + len(diff.changed)
    if changes == 0:
        # Quiet tick - single line so the operator knows we're still alive.
        print(f"[{ts}] .")
        return
    print(f"[{ts}] +{len(diff.new)} new / -{len(diff.lost)} lost / ~{len(diff.changed)} chg")
    for d in diff.new:
        print(f"  + NEW  {d.ip:<16} {d.mac or '':<18} {(d.hostname or ''):<24} {d.vendor or ''}")
    for d in diff.lost:
        print(f"  - LOST {d.ip:<16} {d.mac or '':<18} {(d.hostname or ''):<24} {d.vendor or ''}")
    for before, after in diff.changed:
        print(f"  ~ CHG  {after.mac or '':<18} {before.ip} -> {after.ip}")


def _enrich_devices(reg: DeviceRegistry, devices: tuple[Device, ...]) -> tuple[Device, ...]:
    """Merge registry metadata (label, is_test_system, first_seen, ...) into fresh rows.

    Fresh-scan values win for hostname/vendor/notes when the scan actually
    resolved them (non-None); registry values fill in otherwise. This keeps
    a `--no-resolve` scan from blanking out previously-resolved names.
    """
    out: list[Device] = []
    for d in devices:
        if not d.mac:
            out.append(d)
            continue
        stored = reg.get_by_mac(d.mac)
        if stored is None:
            out.append(d)
            continue
        out.append(Device(
            ip=d.ip,
            mac=d.mac,
            iface=d.iface,
            label=stored.label,
            hostname=d.hostname or stored.hostname,
            vendor=d.vendor or stored.vendor,
            ssh_user=stored.ssh_user,
            ssh_port=stored.ssh_port,
            notes=d.notes or stored.notes,
            is_test_system=stored.is_test_system,
            first_seen=stored.first_seen,
            last_seen=d.last_seen,
        ))
    return tuple(out)


# --------------------------------------------------------------------------- #
# baseline                                                                    #
# --------------------------------------------------------------------------- #


def _cmd_baseline(args: argparse.Namespace) -> int:
    try:
        with DeviceRegistry(state_dir=args.state_dir) as reg:
            if args.action == "save":
                reg.save_baseline(args.name, notes=args.notes)
                print(f"baseline saved: {args.name}")
                return 0
            if args.action == "list":
                names = reg.list_baselines()
                if not names:
                    print("(no baselines)")
                    return 3
                for n in names:
                    print(n)
                return 0
            if args.action == "drop":
                reg.drop_baseline(args.name)
                print(f"baseline dropped: {args.name}")
                return 0
    except (RuntimeError, ValueError) as e:
        print(f"findio: {e}", file=sys.stderr)
        return 2
    return 2


# --------------------------------------------------------------------------- #
# label                                                                       #
# --------------------------------------------------------------------------- #


def _cmd_label(args: argparse.Namespace) -> int:
    try:
        with DeviceRegistry(state_dir=args.state_dir) as reg:
            if args.clear:
                reg.clear_label(args.mac)
                print(f"label cleared on {args.mac}")
                return 0
            if args.label is None:
                print("findio: label requires LABEL argument (or --clear)",
                      file=sys.stderr)
                return 2
            reg.set_label(args.mac, args.label)
            print(f"{args.mac} -> {args.label}")
            return 0
    except ValueError as e:
        print(f"findio: {e}", file=sys.stderr)
        return 2


# --------------------------------------------------------------------------- #
# diff                                                                        #
# --------------------------------------------------------------------------- #


def _cmd_diff(args: argparse.Namespace) -> int:
    try:
        with DeviceRegistry(state_dir=args.state_dir) as reg:
            if args.against:
                diff = reg.diff_against_baseline(args.against)
                heading = f"diff vs baseline {args.against!r}"
            else:
                diff = reg.diff_against_last_scan()
                heading = "diff vs previous scan"
    except (RuntimeError, ValueError) as e:
        print(f"findio: {e}", file=sys.stderr)
        return 2

    if args.json:
        _print_json_diff(diff)
    else:
        _print_plain_diff(diff, heading)
    return 0


# --------------------------------------------------------------------------- #
# version                                                                     #
# --------------------------------------------------------------------------- #


def _cmd_version(_: argparse.Namespace) -> int:
    print(FINDIO_API_VERSION)
    return 0


def _cmd_pick(args: argparse.Namespace) -> int:
    """Resolve a device to SSH target text (or Device fields in --json).

    Two modes:
      --label NAME   non-TUI, O(1) registry lookup
      (default)      open the Textual TUI picker
    Exit codes: 0 picked, 1 cancelled, 2 error, 3 label unknown.
    """
    if args.label:
        from . import pick_by_label
        dev = pick_by_label(args.label, state_dir=args.state_dir)
        if dev is None:
            print(f"label not found: {args.label}", file=sys.stderr)
            return 3
    else:
        try:
            from . import pick_interactive
            dev = pick_interactive(state_dir=args.state_dir)
        except ImportError as e:
            print(str(e), file=sys.stderr)
            return 2
        if dev is None:
            return 1

    if args.json:
        print(json.dumps({
            "findio_api": FINDIO_API_VERSION,
            "device": dev.to_dict(),
        }, indent=2))
    else:
        print(dev.ssh_target)
    return 0


# --------------------------------------------------------------------------- #
# argparse wiring                                                             #
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="findio",
        description="Find devices on your LAN fast.",
        epilog="Only scan networks you are authorized to use.",
    )
    parser.add_argument(
        "--state-dir",
        help="Override state dir (else $FINDIO_STATE_DIR else ~/.findio/).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    # scan ---------------------------------------------------------------- #
    p_scan = sub.add_parser("scan", help="Sweep a subnet; lists visible devices.")
    p_scan.add_argument("--iface", help="Interface name (default: first UP).")
    p_scan.add_argument("--cidr", help="Override CIDR (default: iface's bound CIDR).")
    p_scan.add_argument("--all", action="store_true",
                        help="Scan every UP interface (dual-NIC / BMC use).")
    p_scan.add_argument("--timeout-ms", type=int, default=300,
                        help="Per-host ping timeout in ms. Default 300.")
    p_scan.add_argument("--workers", type=int, default=64,
                        help="Concurrent ping workers. Default 64.")
    p_scan.add_argument("--max-rate", type=float, default=200.0,
                        help="Max pings started per second (0 = unlimited). "
                             "Default 200.")
    p_scan.add_argument("--allow-public", action="store_true",
                        help="Permit sweeping non-private ranges. Off by "
                             "default; only use on networks you own.")
    p_scan.add_argument("--no-record", action="store_true",
                        help="Do not persist this scan to the registry.")
    # Resolution: default ON (the whole point of the tool). --no-resolve for speed.
    resolve_group = p_scan.add_mutually_exclusive_group()
    resolve_group.add_argument(
        "--resolve", dest="resolve", action="store_true", default=True,
        help="Enable rDNS + OUI + SSH banner resolution (default).",
    )
    resolve_group.add_argument(
        "--no-resolve", dest="resolve", action="store_false",
        help="Skip name resolution. Faster; MACs + IPs only.",
    )
    p_scan.add_argument("--resolve-timeout-ms", type=int, default=500,
                        help="Per-probe timeout. Default 500.")
    p_scan.add_argument("--resolve-workers", type=int, default=32,
                        help="Concurrent resolution workers. Default 32.")
    p_scan.add_argument("--no-ssh-probe", action="store_true",
                        help="Skip the SSH banner probe (TCP 22). "
                             "rDNS + OUI still run.")
    # Watch mode: loop, print only deltas per tick.
    p_scan.add_argument("--watch", action="store_true",
                        help="After the primary scan, rescan every --interval "
                             "seconds and print only NEW / LOST / CHANGED.")
    p_scan.add_argument("--interval", type=float, default=10.0,
                        help="Watch tick in seconds (min 2). Default 10.")
    out = p_scan.add_mutually_exclusive_group()
    out.add_argument("--plain", action="store_true",
                     help="Plain-text table (default).")
    out.add_argument("--json", action="store_true",
                     help="JSON envelope - see ARCHITECTURE.md.")
    p_scan.set_defaults(func=_cmd_scan)

    # baseline ------------------------------------------------------------ #
    p_base = sub.add_parser("baseline", help="Manage baselines (snapshot + diff against).")
    base_sub = p_base.add_subparsers(dest="action", required=True, metavar="ACTION")

    p_save = base_sub.add_parser("save", help="Save current scan as named baseline.")
    p_save.add_argument("name")
    p_save.add_argument("--notes", help="Optional note attached to the baseline.")

    base_sub.add_parser("list", help="List all baseline names, newest first.")

    p_drop = base_sub.add_parser("drop", help="Delete a baseline.")
    p_drop.add_argument("name")

    p_base.set_defaults(func=_cmd_baseline)

    # label --------------------------------------------------------------- #
    p_lbl = sub.add_parser("label", help="Set or clear a sticky label on a MAC.")
    p_lbl.add_argument("mac", help="Canonical MAC (AA:BB:CC:DD:EE:FF).")
    p_lbl.add_argument("label", nargs="?",
                       help="Label to assign. Omit with --clear.")
    p_lbl.add_argument("--clear", action="store_true",
                       help="Clear the label on this MAC.")
    p_lbl.set_defaults(func=_cmd_label)

    # diff ---------------------------------------------------------------- #
    p_diff = sub.add_parser("diff", help="Show NEW/CHANGED/LOST vs baseline or last scan.")
    p_diff.add_argument("--against", help="Baseline name. Default: previous scan.")
    p_diff.add_argument("--json", action="store_true",
                        help="JSON envelope instead of plain text.")
    p_diff.set_defaults(func=_cmd_diff)

    # pick ---------------------------------------------------------------- #
    p_pick = sub.add_parser(
        "pick",
        help="Interactive TUI picker, or non-TUI --label lookup. Prints SSH target.",
    )
    p_pick.add_argument("--label", help="Non-interactive: resolve a label via registry.")
    p_pick.add_argument("--json", action="store_true",
                        help="Emit the Device dict instead of ssh_target.")
    p_pick.set_defaults(func=_cmd_pick)

    # version ------------------------------------------------------------- #
    p_ver = sub.add_parser("version", help="Print FINDIO_API_VERSION.")
    p_ver.set_defaults(func=_cmd_version)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "scan" and sys.stderr.isatty():
        print(_AUTHORIZATION_NOTICE, file=sys.stderr)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

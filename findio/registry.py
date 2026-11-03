"""
Registry — SQLite persistence for device history + baselines + diffs.

Schema v1:
  schema_meta       (version)
  devices           (mac PK, first_seen, last_seen, last_ip, last_iface,
                     label UNIQUE, hostname, vendor, ssh_user, ssh_port,
                     notes, is_test_system)
  scans             (id PK, iface, cidr, started_at, finished_at)
  sightings         (id PK, scan_id FK, mac FK, ip, iface, seen_at)
  baselines         (name PK, created_at, notes)
  baseline_members  (baseline_name FK, mac FK, ip, iface, PK(baseline_name, mac))

Migrations applied in order by `_MIGRATIONS` — standard versioned-migration pattern. Every fetch
asserts schema version matches `CURRENT_SCHEMA_VERSION` (ARCHITECTURE.md).

State path resolution (constructor):
  1. `state_dir` argument
  2. `FINDIO_STATE_DIR` env var
  3. default: `~/.findio/`

Phase 2 deliverable.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .diff import compute_diff
from .models import Device, Diff, ScanResult


# --------------------------------------------------------------------------- #
# Schema + migrations                                                         #
# --------------------------------------------------------------------------- #

CURRENT_SCHEMA_VERSION = 1

_V1_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    mac            TEXT PRIMARY KEY NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    last_ip        TEXT,
    last_iface     TEXT,
    label          TEXT UNIQUE,
    hostname       TEXT,
    vendor         TEXT,
    ssh_user       TEXT,
    ssh_port       INTEGER NOT NULL DEFAULT 22,
    notes          TEXT,
    is_test_system INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    iface        TEXT NOT NULL,
    cidr         TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sightings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    mac       TEXT    NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    ip        TEXT    NOT NULL,
    iface     TEXT,
    seen_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sightings_scan ON sightings(scan_id);
CREATE INDEX IF NOT EXISTS idx_sightings_mac  ON sightings(mac);

CREATE TABLE IF NOT EXISTS baselines (
    name       TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    notes      TEXT
);

CREATE TABLE IF NOT EXISTS baseline_members (
    baseline_name TEXT NOT NULL REFERENCES baselines(name) ON DELETE CASCADE,
    mac           TEXT NOT NULL REFERENCES devices(mac)    ON DELETE CASCADE,
    ip            TEXT NOT NULL,
    iface         TEXT,
    PRIMARY KEY (baseline_name, mac)
);
"""

# Append-only. Never edit a shipped migration — add a new entry (ARCHITECTURE.md).
_MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, _V1_SCHEMA),
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _resolve_state_dir(state_dir: Optional[str]) -> Path:
    if state_dir:
        return Path(state_dir).expanduser()
    env = os.environ.get("FINDIO_STATE_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".findio"


def _row_to_device(row: sqlite3.Row) -> Device:
    return Device(
        ip=row["last_ip"] or "",
        mac=row["mac"],
        iface=row["last_iface"],
        label=row["label"],
        hostname=row["hostname"],
        vendor=row["vendor"],
        ssh_user=row["ssh_user"],
        ssh_port=row["ssh_port"],
        notes=row["notes"],
        is_test_system=bool(row["is_test_system"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
    )


# --------------------------------------------------------------------------- #
# DeviceRegistry                                                              #
# --------------------------------------------------------------------------- #


class DeviceRegistry:
    """SQLite-backed device history, baselines, and diff engine."""

    def __init__(self, state_dir: Optional[str] = None) -> None:
        self.state_dir = _resolve_state_dir(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "state.db"
        self._conn = sqlite3.connect(self.db_path, isolation_level=None)  # autocommit
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    # --- lifecycle --------------------------------------------------------- #

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "DeviceRegistry":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # --- migrations -------------------------------------------------------- #

    def _migrate(self) -> None:
        self._conn.executescript(
            "CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER PRIMARY KEY NOT NULL)"
        )
        row = self._conn.execute(
            "SELECT version FROM schema_meta ORDER BY version DESC LIMIT 1"
        ).fetchone()
        current = row["version"] if row else 0
        for version, sql in _MIGRATIONS:
            if version <= current:
                continue
            self._conn.executescript(sql)
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_meta(version) VALUES (?)", (version,)
            )

    def _assert_schema(self) -> None:
        row = self._conn.execute(
            "SELECT version FROM schema_meta ORDER BY version DESC LIMIT 1"
        ).fetchone()
        if not row or row["version"] != CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                f"Schema version mismatch: expected {CURRENT_SCHEMA_VERSION}, "
                f"got {row['version'] if row else 'none'}. "
                f"Delete {self.db_path} or run migrations."
            )

    # --- scan ingest ------------------------------------------------------- #

    def record_scan(self, result: ScanResult) -> int:
        """Insert a scan row + sightings, upsert devices. Returns the scan_id."""
        self._assert_schema()
        cur = self._conn.cursor()
        cur.execute("BEGIN")
        try:
            cur.execute(
                "INSERT INTO scans(iface, cidr, started_at, finished_at) "
                "VALUES (?, ?, ?, ?)",
                (result.iface, result.cidr, result.started_at, result.finished_at),
            )
            scan_id = cur.lastrowid
            for d in result.devices:
                if not d.mac:
                    continue  # Phase 1 guarantees this, defensive skip
                cur.execute(
                    """
                    INSERT INTO devices(mac, first_seen, last_seen, last_ip, last_iface,
                                        hostname, vendor, notes)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        last_ip   = excluded.last_ip,
                        last_iface = excluded.last_iface,
                        hostname  = COALESCE(excluded.hostname, hostname),
                        vendor    = COALESCE(excluded.vendor,   vendor),
                        notes     = COALESCE(excluded.notes,    notes)
                    """,
                    (
                        d.mac,
                        d.last_seen or result.started_at,
                        d.last_seen or result.started_at,
                        d.ip,
                        d.iface,
                        d.hostname,
                        d.vendor,
                        d.notes,
                    ),
                )
                cur.execute(
                    "INSERT INTO sightings(scan_id, mac, ip, iface, seen_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (scan_id, d.mac, d.ip, d.iface, d.last_seen or result.started_at),
                )
            cur.execute("COMMIT")
            return int(scan_id)
        except Exception:
            cur.execute("ROLLBACK")
            raise

    # --- queries ----------------------------------------------------------- #

    def list_current(self, test_systems_only: bool = False) -> tuple[Device, ...]:
        """Devices seen in the most recent scan, reconstructed with full metadata."""
        self._assert_schema()
        row = self._conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return ()
        return self._devices_for_scan(row["id"], test_systems_only=test_systems_only)

    def _devices_for_scan(
        self, scan_id: int, *, test_systems_only: bool = False
    ) -> tuple[Device, ...]:
        sql = """
            SELECT d.*, s.ip AS sight_ip, s.iface AS sight_iface, s.seen_at
              FROM sightings s
              JOIN devices d ON d.mac = s.mac
             WHERE s.scan_id = ?
        """
        if test_systems_only:
            sql += " AND d.is_test_system = 1"
        sql += " ORDER BY s.ip"
        rows = self._conn.execute(sql, (scan_id,)).fetchall()
        return tuple(
            Device(
                ip=r["sight_ip"],
                mac=r["mac"],
                iface=r["sight_iface"],
                label=r["label"],
                hostname=r["hostname"],
                vendor=r["vendor"],
                ssh_user=r["ssh_user"],
                ssh_port=r["ssh_port"],
                notes=r["notes"],
                is_test_system=bool(r["is_test_system"]),
                first_seen=r["first_seen"],
                last_seen=r["seen_at"],
            )
            for r in rows
        )

    def get_by_label(self, label: str) -> Optional[Device]:
        self._assert_schema()
        row = self._conn.execute(
            "SELECT * FROM devices WHERE label = ?", (label,)
        ).fetchone()
        return _row_to_device(row) if row else None

    def get_by_mac(self, mac: str) -> Optional[Device]:
        self._assert_schema()
        row = self._conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()
        return _row_to_device(row) if row else None

    # --- mutations --------------------------------------------------------- #

    def set_label(self, mac: str, label: str) -> None:
        """Attach a sticky label to a MAC. Raises if label collides with another MAC."""
        self._assert_schema()
        existing = self._conn.execute(
            "SELECT mac FROM devices WHERE label = ?", (label,)
        ).fetchone()
        if existing and existing["mac"] != mac:
            raise ValueError(
                f"Label {label!r} already assigned to {existing['mac']}. "
                f"Clear it first with clear_label()."
            )
        updated = self._conn.execute(
            "UPDATE devices SET label = ? WHERE mac = ?", (label, mac)
        ).rowcount
        if updated == 0:
            raise ValueError(f"MAC {mac!r} not in registry — record a scan first.")

    def clear_label(self, mac: str) -> None:
        self._assert_schema()
        self._conn.execute("UPDATE devices SET label = NULL WHERE mac = ?", (mac,))

    def mark_test_system(self, mac: str, is_test: bool = True) -> None:
        self._assert_schema()
        self._conn.execute(
            "UPDATE devices SET is_test_system = ? WHERE mac = ?",
            (1 if is_test else 0, mac),
        )

    # --- baselines --------------------------------------------------------- #

    def save_baseline(self, name: str, notes: Optional[str] = None) -> None:
        """Freeze the most-recent scan's device set as a named baseline."""
        self._assert_schema()
        scan_row = self._conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not scan_row:
            raise RuntimeError(
                "No scans recorded yet — cannot save a baseline. "
                "Call record_scan() first."
            )
        cur = self._conn.cursor()
        cur.execute("BEGIN")
        try:
            cur.execute(
                "INSERT OR REPLACE INTO baselines(name, created_at, notes) "
                "VALUES (?, ?, ?)",
                (name, _now_iso(), notes),
            )
            # Wipe any old members (for REPLACE case) and repopulate from latest scan.
            cur.execute("DELETE FROM baseline_members WHERE baseline_name = ?", (name,))
            cur.execute(
                """
                INSERT INTO baseline_members(baseline_name, mac, ip, iface)
                SELECT ?, mac, ip, iface
                  FROM sightings
                 WHERE scan_id = ?
                """,
                (name, scan_row["id"]),
            )
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise

    def list_baselines(self) -> tuple[str, ...]:
        self._assert_schema()
        rows = self._conn.execute(
            "SELECT name FROM baselines ORDER BY created_at DESC"
        ).fetchall()
        return tuple(r["name"] for r in rows)

    def drop_baseline(self, name: str) -> None:
        self._assert_schema()
        deleted = self._conn.execute(
            "DELETE FROM baselines WHERE name = ?", (name,)
        ).rowcount
        if deleted == 0:
            raise ValueError(f"Baseline {name!r} does not exist.")

    # --- diffs ------------------------------------------------------------- #

    def diff_against_baseline(self, name: str) -> Diff:
        self._assert_schema()
        baseline_row = self._conn.execute(
            "SELECT name FROM baselines WHERE name = ?", (name,)
        ).fetchone()
        if not baseline_row:
            raise ValueError(f"Baseline {name!r} does not exist.")
        previous = self._devices_from_baseline(name)
        current = self.list_current()
        return compute_diff(previous, current)

    def diff_against_last_scan(self) -> Diff:
        """Compare most-recent scan to the one before it."""
        self._assert_schema()
        rows = self._conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 2"
        ).fetchall()
        if len(rows) < 2:
            return Diff()  # no prior scan to compare against
        latest_id, prev_id = rows[0]["id"], rows[1]["id"]
        return compute_diff(
            self._devices_for_scan(prev_id),
            self._devices_for_scan(latest_id),
        )

    def _devices_from_baseline(self, name: str) -> tuple[Device, ...]:
        rows = self._conn.execute(
            """
            SELECT d.*, bm.ip AS bm_ip, bm.iface AS bm_iface
              FROM baseline_members bm
              JOIN devices d ON d.mac = bm.mac
             WHERE bm.baseline_name = ?
             ORDER BY bm.ip
            """,
            (name,),
        ).fetchall()
        return tuple(
            Device(
                ip=r["bm_ip"],
                mac=r["mac"],
                iface=r["bm_iface"],
                label=r["label"],
                hostname=r["hostname"],
                vendor=r["vendor"],
                ssh_user=r["ssh_user"],
                ssh_port=r["ssh_port"],
                notes=r["notes"],
                is_test_system=bool(r["is_test_system"]),
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
            )
            for r in rows
        )

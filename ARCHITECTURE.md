# FindIO Architecture — One-Page Map

For a new maintainer to be productive in an hour. User docs live in `README.md`; the rest is in the code.

`FINDIO_API_VERSION = 1.2.0` — the interop contract locked by this document.

---

## Data flow

```
          ┌────────────────┐         ┌──────────────────┐
          │  findio.py     │         │  from findio     │
          │  (CLI entry)   │         │  import * (lib)  │
          └────────┬───────┘         └────────┬─────────┘
                   │                          │
                   ▼                          ▼
          ┌────────────────────────────────────────────┐
          │           findio/__init__.py               │
          │  PUBLIC API surface (locked by version)    │
          │  Device / ScanResult / Diff                │
          │  Scanner / DeviceRegistry                  │
          │  pick_interactive / pick_by_label          │
          └───────────────────┬────────────────────────┘
                              │
    ┌─────────────────────────┼────────────────────────┐
    │                         │                        │
    ▼                         ▼                        ▼
┌─────────┐          ┌─────────────────┐       ┌──────────────┐
│ cli.py  │          │ ui/tui.py       │       │ library      │
│ argparse│          │ Textual app     │       │ consumers    │
│ → JSON  │          │ (lazy import)   │       │ (scripts) │
└────┬────┘          └────────┬────────┘       └──────┬───────┘
     │                        │                       │
     └────────────┬───────────┴───────────┬───────────┘
                  │                       │
                  ▼                       ▼
      ┌─────────────────────┐   ┌────────────────────┐
      │  scanner.py         │   │  registry.py       │
      │  ICMP sweep +       │   │  SQLite @          │
      │  ARP scrape         │   │  ~/.findio/        │
      │  (platform.py shim) │   │  state.db          │
      └──────────┬──────────┘   └─────────┬──────────┘
                 │                        │
                 ▼                        ▼
         ┌───────────────┐        ┌───────────────┐
         │  resolve.py   │        │   diff.py     │
         │  label→mDNS→  │        │  NEW/CHANGED/ │
         │  NBT→rDNS→    │        │  LOST/RETURN  │
         │  banner→OUI   │        │  + test-sys   │
         └───────────────┘        │  scoring      │
                                  └───────────────┘
```

All three entry paths (CLI, TUI, library) converge on the same `Scanner` + `DeviceRegistry` + `resolve`/`diff` primitives. TUI and CLI are thin; the library is the real API.

---

## Public API surface

Locked by `FINDIO_API_VERSION`. Changes require a version bump and a `test_public_api.py` update in the same commit.

### Types (from `findio.models`)

```python
@dataclass(frozen=True)
class Device:
    ip: str
    mac: Optional[str] = None
    iface: Optional[str] = None
    label: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    ssh_user: Optional[str] = None
    ssh_port: int = 22
    notes: Optional[str] = None
    is_test_system: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> dict: ...
    @property
    def display_name(self) -> str: ...
    @property
    def ssh_target(self) -> str: ...   # "user@ip" or "ip"
```

`ScanResult` and `Diff` are also frozen dataclasses. See `models.py`.

### Functions

```python
from findio import (
    Scanner,                # class — scan()
    DeviceRegistry,         # class — record_scan, list_current, get_by_label,
                            #         set_label, save_baseline,
                            #         diff_against_baseline, diff_against_last_scan
    pick_interactive,       # Textual TUI picker
    pick_by_label,          # non-interactive label → Device lookup
)
```

### Consumer rules

1. Import from `findio` only. Never `findio.scanner`, `findio.ui.tui`, etc.
2. Never mutate a `Device`. Always construct a new one (`dataclass.replace` in stdlib).
3. Check `FINDIO_API_VERSION` MAJOR at consumer startup; refuse to run on a mismatched MAJOR.

---

## JSON CLI contract

Every CLI subcommand with `--json` emits a single JSON object on stdout, one per invocation. Schema locked by `FINDIO_API_VERSION`.

### Shapes (as implemented)

Every `--json` response is a single object with a `findio_api` field equal to the running `FINDIO_API_VERSION`.

```
findio scan --json
  { "findio_api": "...", "scans": [ { "iface", "cidr", "started_at", "finished_at", "devices": [Device, ...] } ] }

findio pick --json
  { "findio_api": "...", "device": Device }          (nothing is printed on cancel; exit code 1)

findio diff [--against NAME] --json
  { "findio_api": "...", "diff": { "new": [Device], "changed": [{"before": Device, "after": Device}],
                                   "lost": [Device], "returned": [Device], "unchanged": [Device] } }
```

`baseline` and `label` print plain text only.

### Exit codes (STABLE)

| Code | Meaning |
|---|---|
| 0 | Success — picked, scanned, diffed, saved |
| 1 | User cancelled (TUI quit with no selection) |
| 2 | Error — scan failure, bad args, DB corruption, missing deps |
| 3 | No result — empty scan, label not matched, baseline missing |

Consumers can branch on exit codes without parsing JSON.

### Schema evolution rules

- **Adding a field to Device or envelope** — MINOR bump (1.0 → 1.1). Consumers on 1.0 keep working; they just don't see the new field.
- **Adding a subcommand or exit code** — MINOR bump.
- **Removing/renaming a field, changing a type, changing an exit code's meaning** — MAJOR bump (1.x → 2.0). Consumers must update.
- **Any schema change requires** updating `test_public_api.py` + this doc + `__init__.py::FINDIO_API_VERSION` in the same commit.

---

## State directory

Single SQLite database for device history, labels, baselines.

**Resolution order:**
1. `DeviceRegistry(state_dir=...)` argument
2. `FINDIO_STATE_DIR` env var
3. Default: `~/.findio/` (user-global — survives across Dropbox, CWD, projects)

**Why user-global default:** labels set from the CLI must be visible to any script that later calls `findio pick`. A synced-folder path invites SQLite conflict files when two machines write at once. The user home is clean.

**Schema:** see `findio/registry.py` docstring. Migrations via `_MIGRATIONS` tuple + `CURRENT_SCHEMA_VERSION`.

---

## Dependency policy

**Library path (Scanner, DeviceRegistry, CLI `--json`):** Python 3.10+ standard library only.

**TUI path (`pick_interactive`, `findio` with no args):** additionally:
- `textual`
- `rich`

(the `tui` extra in `pyproject.toml`). Lazy-imported inside `findio/ui/tui.py`. Library consumers that never open the TUI do not install these.

Enforced by `tests/test_lazy_tui_import.py` — imports `findio` with textual removed from `sys.modules` and asserts no ImportError.

---

## Integration

Scripts can shell out to `findio pick --json` (parse stdout, branch on the exit code) or import from `findio` in the same environment:

```python
from findio import pick_by_label
device = pick_by_label("bench-2")   # None if unknown
```

Both paths return the same `Device` contract.

---

## Safety

The scanner refuses non-private ranges without `--allow-public`, refuses sweeps above 1024 hosts, and paces ping starts (`--max-rate`). See `README.md`.

---

## Pointers

- User docs + scope honesty → `README.md`
- Device / ScanResult / Diff dataclass definitions → `findio/models.py`
- Public API stubs (spec-by-code) → `findio/__init__.py`
- API contract tests → `findio/tests/test_public_api.py`

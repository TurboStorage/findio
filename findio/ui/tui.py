"""
Textual TUI — interactive device picker.

Lazy-imports `textual` + `rich` INSIDE the entry function. The module itself
must be importable without those packages installed (library consumers that
never call `run_tui()` must not be forced to install Textual).

Enforced by `tests/test_lazy_tui_import.py` — imports `findio` with textual
removed from sys.modules and asserts no ImportError.

Keybinds:
  Up/Down   navigate
  Enter     pick selected device (returns Device to caller)
  r         rescan
  w         toggle watch mode (rescan on a timer, highlight NEW/LOST/CHANGED)
  q / Esc   cancel (returns None)
  header    click a column header to sort (click again to reverse)

The picker only returns the chosen Device; it does not launch SSH itself.
"""

from __future__ import annotations

from typing import Optional

from ..models import Device


_TEXTUAL_HINT = (
    "FindIO TUI requires `textual` and `rich`. Install with:\n"
    "    pip install --user textual rich\n"
    "Library consumers that don't need the picker can skip this — "
    "`findio scan --json` and `findio pick --label X` work without it."
)


def _lazy_import_textual():
    """Import textual/rich on demand. Raises clean error if missing."""
    try:
        import textual  # noqa: F401
        import rich  # noqa: F401
    except ImportError as e:
        raise ImportError(_TEXTUAL_HINT) from e


def run_tui(state_dir: Optional[str] = None) -> Optional[Device]:
    """Open the picker TUI. Returns chosen Device or None if cancelled.

    The TUI opens a live scan on mount (so the operator sees current state,
    not a stale registry snapshot), enriches against the registry, and lets
    the user pick a row. Network work happens on a worker thread to keep the
    UI responsive.
    """
    _lazy_import_textual()

    # Imports deferred until after the guard — if textual is missing we want
    # the clean ImportError message, not a confusing NameError on module load.
    from ._app import FindIOPickerApp

    app = FindIOPickerApp(state_dir=state_dir)
    app.run()
    return app.chosen

"""
UI submodule — TUI code lives here.

This package intentionally re-exports nothing. TUI dependencies (textual,
rich) are lazy-imported inside `findio.ui.tui` only, so library consumers
like other tools can `from findio import DeviceRegistry, Scanner` without pulling
Textual into their venv.

See ARCHITECTURE.md.
"""

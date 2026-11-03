# Changelog

## 1.2.0 - public release preparation

### Added
- Safety: public (non-private, non-link-local) ranges are refused unless `--allow-public` / `allow_public=True`.
- Safety: `--max-rate` (default 200 pings/second) paces ping starts; default workers lowered from 128 to 64.
- Authorization notice on stderr when `findio scan` runs in an interactive terminal; also in `--help`.
- `pyproject.toml` packaging with a `findio` console script and an optional `tui` extra.
- MIT `LICENSE`, `docs/sample-output.txt` (synthetic addresses).
- Tests for range refusal, rate pacing and the new flags (188 tests total).

### Changed
- README rewritten to describe what the code actually does; ARCHITECTURE JSON contract corrected to match the implemented output.
- Test fixtures and test data use documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 7042 documentation MACs.
- CLI output is ASCII only; the previous arrow character crashed `scan` on consoles with a non-UTF-8 code page (for example Windows cp1252).

### Removed
- Unimplemented stubs: `findio/ssh.py` and `diff.score_test_system` (both only raised `NotImplementedError`).
- Internal planning and contributor-agent documents.

## Earlier (internal, unreleased)
- 1.0.0-1.1.x: scanner, registry with baselines and labels, diff, name resolution, Textual picker with watch mode.

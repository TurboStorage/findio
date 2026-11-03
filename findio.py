#!/usr/bin/env python3
"""
FindIO entrypoint — thin shim.

Usage:
    python3 findio.py [scan|pick|baseline|label|diff|version] [args...]

All logic lives in the `findio` package. See README.md / ARCHITECTURE.md.
"""

import sys

from findio.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""
Run Helix from a source checkout: python helix.py -u NAME

The program lives in the helix_osint package (helix_osint/cli.py). This file
is not installed: an installed Helix is started with `helix-osint`, `helix`
or `python -m helix_osint`.
"""

from helix_osint.cli import main

if __name__ == "__main__":
    main()

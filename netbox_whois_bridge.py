#!/usr/bin/env python3
"""Compatibility wrapper for running the package as a script."""

from netbox_whois_bridge.cli import main


if __name__ == "__main__":
    raise SystemExit(main())

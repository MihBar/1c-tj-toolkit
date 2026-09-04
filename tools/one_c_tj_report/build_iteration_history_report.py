#!/usr/bin/env python3
"""Universal saved-result PDF entry point; shared implementation in report_cli."""
try:
    from .report_cli import main
except ImportError:
    from report_cli import main

if __name__ == '__main__':
    raise SystemExit(main(kind='history'))

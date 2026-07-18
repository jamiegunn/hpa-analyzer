#!/usr/bin/env python3
"""Convenience launcher: python3 hpa-analyzer.py <chart-directory>"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hpaanalyzer.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())

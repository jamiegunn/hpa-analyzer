#!/usr/bin/env python3
"""Deprecated launcher. The supported command is ./bin/hpa-analyzer.

This file used to be the documented way to run the tool:

    python3 hpa-analyzer.py ./my-service

It is kept, refusing, rather than deleted. Someone whose CI job or shell
history still holds that line deserves a sentence telling them where the
command went; `No such file or directory` sends them to a search engine.

It refuses through exactly the same code path as `python3 -m hpaanalyzer`
(__main__._require_image), so there is one refusal message, one exit code and
one place to change them. A second, hand-copied refusal here would drift.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hpaanalyzer.__main__ import _require_image, main

if __name__ == "__main__":
    raise SystemExit(_require_image() or main())

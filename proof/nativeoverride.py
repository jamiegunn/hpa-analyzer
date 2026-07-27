"""Lets the proof scripts run the CLI natively, and says why that is allowed.

`python3 -m hpaanalyzer` refuses to run outside the pinned container image
(hpaanalyzer/__main__.py: _require_image). The proof scripts have to run that
exact command as a real subprocess - the whole point of this directory is that
its numbers are program output rather than recollection - and they run on
machines with no docker daemon, including this repository's own sandbox, where
`docker build` cannot reach a registry at all. A guard that made the evidence
layer unrunnable would be protecting the tool by deleting the only thing that
shows the tool is right.

So importing this module sets HPA_ANALYZER_ALLOW_NATIVE=1 in this process's
environment, and every subprocess the proof scripts spawn inherits it - each
of them builds its env with dict(os.environ, ...) rather than from scratch, so
there is no second place to keep in sync.

setdefault, not assignment: a caller who has deliberately set the variable to
something else (to watch the refusal happen, say) keeps their value.

WHAT THIS COSTS
---------------
It means the proof scripts measure the analyzer running against whatever helm
is on the host, not against the pinned one. That is not hidden - it is why
p12_helpers.py and the bar2 scripts pass `--helm off` explicitly, pinning the
mode from the command line so the measurement is identical on a machine with
helm and one without. Where a script does NOT pin the mode, its numbers are
host-dependent and it says so in its own docstring.
"""

import os

os.environ.setdefault("HPA_ANALYZER_ALLOW_NATIVE", "1")

#!/usr/bin/env python3
"""PROOF R3, Bar 1: the constraint engine is a PORT, and here is the diff.

hpaanalyzer/kubeversion.py decides which Kubernetes minors a chart supports,
and every severity R3 assigns hangs off that answer. Asserting it against
hand-written expectations would only prove that the same person wrote the code
and the test. So this script does not use expectations at all: it builds the
actual library helm links against - github.com/Masterminds/semver/v3 v3.3.0,
pinned by helm v3.16.4's go.mod - wraps it in the exact five lines of
helm/pkg/chartutil/compatible.go:IsCompatibleRange, and compares the two
implementations over every (constraint, version) pair in a generated matrix.

A disagreement on ANY pair fails this script. There is no tolerance and no
sampling: the matrix is the test.

The result is frozen into tests/oracle_semver.json so the unit suite can
assert the same conformance with no Go toolchain and no network. Regenerate
it by running this script with --freeze; it will refuse to overwrite the file
if the live comparison does not pass first.

Requires: go, git, network. Run: python3 proof/p3_oracle.py [--freeze]
"""

import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from hpaanalyzer import kubeversion as kv          # noqa: E402

FROZEN = os.path.join(REPO, "tests", "oracle_semver.json")

HELM_TAG = "v3.16.4"
SEMVER_TAG = "v3.3.0"      # helm v3.16.4 go.mod: github.com/Masterminds/semver/v3

_ORACLE_GO = r'''package main

// Mirrors helm/pkg/chartutil/compatible.go:IsCompatibleRange EXACTLY,
// including its "unparseable constraint -> false" behaviour.

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Masterminds/semver/v3"
)

func isCompatibleRange(constraint, ver string) bool {
	sv, err := semver.NewVersion(ver)
	if err != nil {
		return false
	}
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false
	}
	return c.Check(sv)
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "\t", 2)
		fmt.Fprintf(w, "%t\n", isCompatibleRange(p[0], p[1]))
	}
}
'''

# Constraints a real Chart.yaml carries, plus the shapes that break naive
# implementations: hyphen ranges (spaces are significant), wildcards, tilde,
# caret, OR, comma-vs-space AND, prerelease comparators, and strings that are
# not constraints at all.
CONSTRAINTS = [
    ">=1.29.0-0", ">=1.29.0", ">= 1.29.0-0", ">=1.23.0-0", ">=1.33.0-0",
    ">=1.20.0-0 <1.22.0-0", ">=1.20.0-0, <1.22.0-0", ">=1.21 <1.25",
    ">1.24", ">1.24.0", "<1.25", "<=1.24", "=1.24.7", "1.24.7", "1.24",
    "1.24.x", "1.x", "x", "*", "1.*", "~1.24", "~1.24.3", "~>1.24",
    "^1.24.3", "^1.24", "^0.2.3", "!=1.25.0", "!=1.25.x",
    "1.20 - 1.24", "1.20.0 - 1.24.9", ">=1.21 <1.23 || >=1.25 <1.27",
    ">=1.19.0-0 <1.22.0-0 || >=1.25.0-0",
    ">=1.30.0-0 <1.20.0-0",                 # deliberately empty
    "", "  ", ">= v1.24.0", "v1.24.0",
    ">=1.24.0-0 !=1.26.0", "1.24 || 1.26 || 1.28",
    # not constraints - helm treats each of these as "install nowhere"
    "1,24", ">=1.24 and <1.26", "latest", ">>1.24", "1.24-1.26",
    ">= 1.24.0 <", "kubeVersion", "1.24.0.0.0",
]

VERSIONS = (
    [f"1.{m}.0" for m in range(14, 41)]
    + [f"1.{m}.7" for m in range(20, 34)]
    + ["1.24.999", "1.21.3", "1.21.2",
       # managed distributions: these are semver PRERELEASES
       "1.29.3-gke.1093000", "1.30.0-eks-a5ec690", "1.28.9-aks1",
       "v1.27.4", "1.27", "1", "2.0.0", "0.9.0",
       # not versions
       "unknown", "", "v", "1.2.3.4"]
)


def _sh(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def build_oracle(work):
    src = os.path.join(work, "semver")
    _sh(["git", "clone", "--depth", "1", "-b", SEMVER_TAG,
         "https://github.com/Masterminds/semver.git", src])
    mod = os.path.join(work, "oracle")
    os.makedirs(mod)
    with open(os.path.join(mod, "main.go"), "w") as f:
        f.write(_ORACLE_GO)
    with open(os.path.join(mod, "go.mod"), "w") as f:
        f.write("module oracle\n\ngo 1.21\n\n"
                f"require github.com/Masterminds/semver/v3 {SEMVER_TAG}\n\n"
                f"replace github.com/Masterminds/semver/v3 => {src}\n")
    env = dict(os.environ, GOFLAGS="-mod=mod", GOPROXY="off", GOSUMDB="off")
    _sh(["go", "build", "-o", "oracle", "."], cwd=mod, env=env)
    return os.path.join(mod, "oracle")


def ask_oracle(binary, pairs):
    payload = "".join(f"{c}\t{v}\n" for c, v in pairs)
    out = subprocess.run([binary], input=payload, capture_output=True,
                         text=True, check=True).stdout
    lines = out.strip().split("\n")
    assert len(lines) == len(pairs), (len(lines), len(pairs))
    return [ln == "true" for ln in lines]


def ours(constraint, version):
    """hpaanalyzer's answer, through the same IsCompatibleRange shape."""
    try:
        con = kv.parse_constraint(constraint)
    except kv.ConstraintError:
        return False
    return con.check(version)


def main():
    freeze = "--freeze" in sys.argv
    print(__doc__.split("Requires:")[0].rstrip())
    print("=" * 76)

    pairs = [(c, v) for c in CONSTRAINTS for v in VERSIONS]
    print(f"matrix: {len(CONSTRAINTS)} constraints x {len(VERSIONS)} versions "
          f"= {len(pairs)} pairs")
    print(f"oracle: github.com/Masterminds/semver/v3 {SEMVER_TAG}, the version "
          f"pinned by helm {HELM_TAG}")
    print()

    work = tempfile.mkdtemp(prefix="hpa-oracle-")
    try:
        binary = build_oracle(work)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print("could not build the Go oracle:", e)
        print("This script needs go + git + network. The frozen table in")
        print(f"  {os.path.relpath(FROZEN, REPO)}")
        print("is what the unit suite checks against; it was produced by a "
              "run of this script that did pass.")
        return 2

    expected = ask_oracle(binary, pairs)
    got = [ours(c, v) for c, v in pairs]

    mismatches = [(c, v, e, g)
                  for (c, v), e, g in zip(pairs, expected, got) if e != g]

    print("CLAIM 1: hpaanalyzer.kubeversion agrees with the real library on")
    print("         every pair in the matrix.")
    print(f"         pairs compared : {len(pairs)}")
    print(f"         disagreements  : {len(mismatches)}")
    for c, v, e, g in mismatches[:20]:
        print(f"           {c!r} vs {v!r}: helm={e} ours={g}")
    if len(mismatches) > 20:
        print(f"           ... and {len(mismatches) - 20} more")

    # The two facts the R3 severity logic is built on, stated as claims so a
    # reviewer sees them proven rather than asserted in a docstring.
    print()
    print("CLAIM 2: a constraint that does not parse is not ignored by helm -")
    print("         IsCompatibleRange returns false, so the chart installs")
    print("         on NO cluster. (This is why R3 reports it, and reports")
    print("         it as critical.)")
    bad = ">=1.24 and <1.26"
    o_bad = ask_oracle(binary, [(bad, v) for v in
                                ["1.24.0", "1.25.0", "1.30.0", "1.20.0"]])
    print(f"         {bad!r} satisfied by any of 1.20/1.24/1.25/1.30: "
          f"{any(o_bad)}")
    claim2 = not any(o_bad)

    print()
    print("CLAIM 3: `>=1.29.0` does not match a managed-distribution version")
    print("         string, and `>=1.29.0-0` does. This is not folklore; it")
    print("         is the prerelease rule in constraints.go.")
    probes = [(">=1.29.0", "1.29.3-gke.1093000"),
              (">=1.29.0", "1.30.0-eks-a5ec690"),
              (">=1.29.0", "1.30.0"),
              (">=1.29.0-0", "1.29.3-gke.1093000"),
              (">=1.29.0-0", "1.30.0-eks-a5ec690")]
    o_pre = ask_oracle(binary, probes)
    for (c, v), r in zip(probes, o_pre):
        print(f"         {c:<12} vs {v:<22} -> {r}")
    claim3 = o_pre == [False, False, True, True, True]
    print(f"         our engine agrees: "
          f"{[ours(c, v) for c, v in probes] == o_pre}")
    claim3 = claim3 and [ours(c, v) for c, v in probes] == o_pre

    ok = not mismatches and claim2 and claim3
    print()
    print("=" * 76)
    if not ok:
        print("NOT PROVEN")
        return 1

    print("Bar 1 met for the constraint engine: it is a faithful port, checked")
    print("against the original rather than against its author's memory.")

    if freeze:
        table = {"semver_version": SEMVER_TAG, "helm_version": HELM_TAG,
                 "cases": [[c, v, e] for (c, v), e in zip(pairs, expected)]}
        with open(FROZEN, "w") as f:
            json.dump(table, f, indent=0, sort_keys=False)
            f.write("\n")
        print(f"froze {len(pairs)} oracle answers into "
              f"{os.path.relpath(FROZEN, REPO)}")
    else:
        print("(re-run with --freeze to regenerate tests/oracle_semver.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

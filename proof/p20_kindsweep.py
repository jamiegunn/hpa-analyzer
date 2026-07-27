#!/usr/bin/env python3
"""R18. The corpus could not have found R16 or R17, and here is the instrument
that can.

WHAT THIS ROUND IS ABOUT
------------------------
R16 and R17 both found real defects. Neither was found by the test suite or by
the 35-chart corpus; both were found by a chart I wrote by hand after already
suspecting the answer. That is not a process, it is luck with good PR, and the
measurement that opened R18 says why.

Task #67 ran the whole corpus under eight flag combinations - 44 targets, 352
analyzer runs - and counted what it actually presents to the tool:

    workload objects rendered   42
    Deployment                  40  (39 charts)
    StatefulSet                  1
    CronJob                      1
    DaemonSet, ReplicaSet, ReplicationController, Job, Rollout   NEVER PARSED

    rule IDs in the source     138
    ever fire                   90  (65%)
    never fire                  48
    of those 48, the number gated on a cluster probe, --measured or
    --cross-check, i.e. on something this sandbox cannot produce:   0

    distinct (kind, hpa, replicas, resources, heap) tuples presented:
        17 of a nominal 1024 = 1.7%

Every one of the 48 silent rules is waiting for a chart shape, not a cluster.
`replicas == 1 and no HPA`. `limit < request`. `MaxRAMPercentage >= 85`. `-Xmx`
and `MaxRAMPercentage` together. Java 9/10/12-16/18-20. `apiVersion: v1` in
Chart.yaml. So the corpus is not short of a Kubernetes cluster. It is short of
charts, in exactly two dimensions - five kinds it never parses, and 98.3% of the
field-shape space it never presents - and those two dimensions are precisely
where R16 and R17 lived.

WHAT THIS SCRIPT IS
-------------------
An instrument, not an assertion. proof/chartgen.py generates charts over the
decision space; this runs the analyzer over them and applies two mechanical
oracles to the JSON:

  O1  KIND DIVERGENCE. Tier A generates one chart shape in eight kinds and
      varies nothing else. Any rule that fires on some kinds and not others is
      reported. Any variant whose score, grade or `graded` flag differs from the
      Deployment variant's is reported.

  O2  SILENCE WITH STRUCTURE PRESENT. A chart declared a workload; if the tool
      reports it ungraded, or reports nothing at all from a rule family that
      fired on the Deployment variant, that is reported.

Neither oracle knows what any kind list in hpaanalyzer/kube.py contains. Neither
reads the tool's source at all - both work purely off `--json` output. An
instrument that consults kube.SCALABLE_KINDS to decide what ought to happen
cannot be evidence about whether kube.SCALABLE_KINDS is right.

A QUESTION IS NOT A DEFECT
--------------------------
Divergence between kinds is often correct: telling a DaemonSet to add an HPA is
worse than saying nothing, and R16 shipped that asymmetry deliberately. So the
output is a QUESTION LIST, and each entry is dispositioned into
proof/kindsweep_expect.txt with a one-line argued reason, or reproduced with a
standalone chart and fixed. That file started EMPTY and is filled one line at a
time; every line in it is a claim someone can argue with.

FORCED DELTAS. Charts that differ only in `kind` do not exist - the API forbids
it. chartgen.DELTAS records every unavoidable difference and this script prints
it next to any divergence it reports, so nobody attributes `restartPolicy:
Never` to a kind list.

THE ACCEPTANCE TEST, FIXED BEFORE THE INSTRUMENT EXISTED
--------------------------------------------------------
An instrument that cannot rediscover the last two rounds is not evidence about
the next one. So `--acceptance` runs the whole thing against 713774c - the last
commit before R16 - with an EMPTY expectations file, and requires that it finds,
without being told to look:

  AT1  ReplicaSet diverging from Deployment on a chart differing only in kind
  AT2  Rollout diverging from Deployment
  AT3  ReplicationController coming back graded=false
  AT4  DaemonSet, with no HPA, scoring BETTER than the Deployment while the
       whole HP family stays silent - R16's defect
  AT5a the code that decides what is suspicious contains no kind list copied
       from kube.py and no rule ID hard-coded as interesting

and then, on HEAD:

  AT6  AT1-AT3 no longer appear. R17 fixed them; if the instrument still
       reports them, the instrument is wrong, and that is the finding.
  AT7  AT4 still appears, for dispositioning as expected.

TWO THINGS THAT WENT WRONG, RECORDED RATHER THAN TIDIED AWAY
------------------------------------------------------------
1. The first design had ONE Tier A baseline, with an HPA present. It passed
   AT1-AT3 and FAILED AT4 - because R16's defect is about what the tool does
   when a kind that cannot be autoscaled has NO HPA, and a sweep that always
   ships an HPA never asks that question. The design grew a second baseline; the
   acceptance criteria were not touched. See chartgen.BASELINES.

2. AT5 is reported as two numbers because the strict version FAILS. The design
   fixed AT5 over the instrument, and the instrument is clean. The first version
   of the check also grepped the GENERATOR, and found that chartgen's prose
   cites two rule/list names as the reason particular axes exist. That is true:
   the axes were chosen with the silent-rule list in view, so this is targeted
   coverage, not blind coverage. Deleting two comments would make the grep pass
   and make the provenance of the axes less honest, so AT5b is reported failing
   on every run instead. The tokens appear in no executable statement, and
   AT5b-exec asserts that separately - that is the part that would actually
   invalidate the result.

SANDBOX CAVEAT (same as p14/p17)
--------------------------------
Since R12 the supported command is `hpa-analyzer <dir>`, which runs the pinned
image. This container has no docker daemon, so the module is run directly with
HPA_ANALYZER_ALLOW_NATIVE=1 via proof/nativeoverride.py. Every run here passes
`--helm off`, so the numbers are identical on a machine with helm and one
without.
"""

import argparse
import collections
import concurrent.futures
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402
import chartgen as gen  # noqa: E402
import corpus_charts  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECT_DEFAULT = os.path.join(HERE, "kindsweep_expect.txt")
PRE_R16 = "713774c"          # "R15: six flags the tool accepted..."
WORKERS = int(os.environ.get("KINDSWEEP_WORKERS", "4"))
FLAGS = ["--helm", "off"]

# AT5. These are the answer keys from R16 and R17. If any appears in this file
# below its own declaration, the acceptance test is void: it would mean the
# oracle was told what to look for.
FORBIDDEN = ["SCALABLE_KINDS", "REPLICA_MANAGED", "SCALE_CANDIDATE",
             "HP050", "AV010", "HP002", "scale_class"]


def _self_check():
    src = open(os.path.abspath(__file__)).read()
    body = src.split("FORBIDDEN = [", 1)[1].split("]", 1)[1]
    return [t for t in FORBIDDEN if t in body]


def _executable_tokens(path):
    """Every token of `path` except comments and standalone docstrings. A
    forbidden name in a comment cannot steer an oracle; one in a statement can,
    and only the second is grounds for voiding the run."""
    out = []
    with open(path) as fh:
        for tok in tokenize.generate_tokens(io.StringIO(fh.read()).readline):
            if tok.type == tokenize.COMMENT:
                continue
            if (tok.type == tokenize.STRING
                    and tok.line.strip()[:3] in ('"""', "'''")):
                continue
            out.append(tok.string)
    return " ".join(out)


# ---------------------------------------------------------------------------
# running the tool
# ---------------------------------------------------------------------------
def run(repo, target):
    fd, jp = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    env = dict(os.environ, HPA_ANALYZER_ALLOW_NATIVE="1")
    try:
        p = subprocess.run([sys.executable, "-m", "hpaanalyzer", target,
                            "--json", jp] + FLAGS,
                           cwd=repo, env=env, capture_output=True, text=True,
                           timeout=300)
        try:
            with open(jp) as fh:
                return json.load(fh)
        except Exception:                                        # noqa: BLE001
            return {"_error": p.stderr[-400:], "_rc": p.returncode,
                    "findings": []}
    finally:
        os.unlink(jp)


def run_many(repo, targets):
    """targets: [(key, dir), ...] -> {key: json}. Order-independent, so the
    thread pool cannot change a result."""
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(run, repo, d): k for k, d in targets}
        for f in concurrent.futures.as_completed(futs):
            out[futs[f]] = f.result()
    return out


# ---------------------------------------------------------------------------
# the oracles
# ---------------------------------------------------------------------------
def questions(res):
    """O1 + O2 over one Tier A sweep. Returns a list of dicts. Knows nothing
    about Kubernetes beyond the kind names it generated."""
    qs = []
    kinds = list(res)
    rule_kinds = collections.defaultdict(set)
    for k, d in res.items():
        for f in d.get("findings", []):
            rule_kinds[f["rule"]].add(k)

    base = res.get("Deployment", {})
    base_rules = {f["rule"] for f in base.get("findings", [])}
    base_fams = collections.Counter(f["rule"][:2]
                                    for f in base.get("findings", []))

    # O1a: verdict divergence from the Deployment variant
    for k in kinds:
        if k == "Deployment":
            continue
        d = res[k]
        diffs = ["%s %r vs %r" % (fld, d.get(fld), base.get(fld))
                 for fld in ("score", "grade", "graded")
                 if d.get(fld) != base.get(fld)]
        if diffs:
            qs.append({"oracle": "O1a", "kind": k, "what": "; ".join(diffs),
                       "delta": gen.DELTAS[k]})

    # O1b: a rule that fires on some kinds and not others
    for r in sorted(rule_kinds):
        on = rule_kinds[r]
        off = [k for k in kinds if k not in on]
        if off and on:
            qs.append({"oracle": "O1b", "rule": r,
                       "fires_on": sorted(on), "silent_on": sorted(off),
                       "delta": "; ".join("%s: %s" % (k, gen.DELTAS[k])
                                          for k in sorted(off))})

    # O2: structure present, tool silent
    for k in kinds:
        d = res[k]
        if d.get("_error"):
            qs.append({"oracle": "O2", "kind": k,
                       "what": "the run produced no JSON at all",
                       "delta": gen.DELTAS[k]})
            continue
        if d.get("graded") is False:
            qs.append({"oracle": "O2", "kind": k,
                       "what": "a workload of this kind was generated and the "
                               "tool reports graded=false (%s)"
                               % (d.get("grade") or "no grade"),
                       "delta": gen.DELTAS[k]})
        fams = collections.Counter(f["rule"][:2]
                                   for f in d.get("findings", []))
        gone = sorted(f for f in base_fams if not fams.get(f))
        if gone and k != "Deployment":
            qs.append({"oracle": "O2", "kind": k,
                       "what": "rule families entirely silent that the "
                               "Deployment variant raised: " + ", ".join(gone),
                       "delta": gen.DELTAS[k]})
        n = len(d.get("findings", []))
        if base_rules and n < len(base_rules) * 0.5:
            qs.append({"oracle": "O2", "kind": k,
                       "what": "%d findings against the Deployment variant's "
                               "%d - less than half" % (n, len(base_rules)),
                       "delta": gen.DELTAS[k]})
    return qs


def qkey(q):
    """The stable name a disposition line in kindsweep_expect.txt refers to."""
    if q["oracle"] == "O1b":
        return "O1b:" + q["rule"]
    return "%s:%s" % (q["oracle"], q["kind"])


# ---------------------------------------------------------------------------
# sweeps
# ---------------------------------------------------------------------------
def tier_a(repo, root, baseline):
    made = gen.write_kind_sweep(root, baseline)
    return run_many(repo, [(kind, d) for _n, kind, d, _desc in made])


def tier_b(repo, root):
    made = gen.write_shape_sweep(root)
    res = run_many(repo, [(name, d) for name, _kw, d, _desc in made])
    kw_of = {name: kw for name, kw, _d, _desc in made}
    fired = collections.Counter()
    rule_kinds = collections.defaultdict(set)
    errs = []
    for name, r in sorted(res.items()):
        if r.get("_error"):
            errs.append((name, (r["_error"].strip().splitlines() or [""])[-1]))
        for f in r.get("findings", []):
            fired[f["rule"]] += 1
            rule_kinds[f["rule"]].add(kw_of[name]["kind"])
    return made, fired, rule_kinds, errs


def declared_rule_ids(repo):
    """Every rule ID the source declares. This DOES read the tool's source -
    but only to count coverage afterwards, never to decide what is suspicious.
    The oracles above never see it."""
    ids = set()
    d = os.path.join(repo, "hpaanalyzer")
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".py"):
            with open(os.path.join(d, fn)) as fh:
                ids |= set(re.findall(r'rule_id="([A-Z]{2}\d{3})"', fh.read()))
    return ids


def corpus_fired(repo, root):
    """What the 35 hand-written charts light up, measured now rather than
    quoted from a table that can go stale."""
    made = corpus_charts.write_corpus(root)
    res = run_many(repo, [(n, os.path.join(root, n)) for n, _b in made])
    fired = set()
    for r in res.values():
        fired |= {f["rule"] for f in r.get("findings", [])}
    return len(made), fired


# ---------------------------------------------------------------------------
def sweep(repo, expect, tiers, verbose=True):
    """One full run against one tree. Returns the JSON-able result blob."""
    root = tempfile.mkdtemp(prefix="r18-sweep-")
    out = {"repo": repo, "expect_entries": len(expect),
           "tier_a": {}, "questions": {}}
    try:
        if "a" in tiers:
            for baseline in sorted(gen.BASELINES):
                res = tier_a(repo, root, baseline)
                qs = questions(res)
                out["tier_a"][baseline] = {
                    k: {"score": v.get("score"), "grade": v.get("grade"),
                        "graded": v.get("graded"),
                        "findings": len(v.get("findings", [])),
                        "rules": sorted({f["rule"]
                                         for f in v.get("findings", [])})}
                    for k, v in res.items()}
                out["questions"][baseline] = qs
                if verbose:
                    _print_tier_a(baseline, res, qs, expect)

        if "b" in tiers:
            made, fired, rule_kinds, errs = tier_b(repo, root)
            croot = tempfile.mkdtemp(prefix="r18-corpus-")
            try:
                n_corpus, cfired = corpus_fired(repo, croot)
            finally:
                shutil.rmtree(croot, ignore_errors=True)
            declared = declared_rule_ids(repo)
            new = sorted(fired.keys() - cfired)
            out["tier_b"] = {
                "charts": len(made), "fired": dict(fired),
                "rule_kinds": {r: sorted(v) for r, v in rule_kinds.items()},
                "corpus_charts": n_corpus, "corpus_fired": sorted(cfired),
                "declared": len(declared), "new_rules": new,
                "errors": errs}
            if verbose:
                _print_tier_b(made, fired, rule_kinds, errs,
                              declared, cfired, new, n_corpus)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return out


def _print_tier_a(baseline, res, qs, expect):
    print("\n=== TIER A [%s]: %d kinds, one shape, nothing else varying ==="
          % (baseline, len(gen.KINDS)))
    print("  %-22s %-7s %-5s %-12s %s"
          % ("kind", "score", "grade", "graded", "findings"))
    for k in gen.KINDS:
        d = res.get(k, {})
        print("  %-22s %-7s %-5s %-12s %d"
              % (k, d.get("score"), d.get("grade"), d.get("graded"),
                 len(d.get("findings", []))))
    undis = [q for q in qs if qkey(q) not in expect]
    print("\n  questions raised : %d" % len(qs))
    print("  dispositioned    : %d" % (len(qs) - len(undis)))
    print("  OPEN             : %d\n" % len(undis))
    for q in undis:
        if q["oracle"] == "O1b":
            print("  [O1b] %s fires on %s, silent on %s"
                  % (q["rule"], ", ".join(q["fires_on"]),
                     ", ".join(q["silent_on"])))
        else:
            print("  [%s] %s: %s" % (q["oracle"], q["kind"], q["what"]))
        print("        forced delta: %s" % q["delta"])


def _print_tier_b(made, fired, rule_kinds, errs, declared, cfired, new,
                  n_corpus):
    print("\n=== TIER B: pairwise covering array over six axes ===")
    print("  charts generated       : %d" % len(made))
    for axis, values in gen.AXES:
        seen = collections.Counter(kw[axis] for _n, kw, _d, _s in made)
        print("    %-10s %d/%d values  %s"
              % (axis, len(seen), len(values),
                 " ".join("%s=%d" % (v, seen.get(v, 0)) for v in values)))
    print("  rule IDs declared      : %d" % len(declared))
    print("  fired by this sweep    : %d" % len(fired))
    print("  fired by the %d-chart hand-written corpus : %d"
          % (n_corpus, len(cfired)))
    print("  NEW - fired here, never by the corpus     : %d" % len(new))
    if new:
        for i in range(0, len(new), 10):
            print("      " + " ".join(new[i:i + 10]))
    still = sorted(declared - set(fired) - cfired)
    print("  still silent everywhere : %d" % len(still))
    if errs:
        print("  charts that produced no JSON: %d" % len(errs))
        for n, e in errs[:5]:
            print("     %s  %s" % (n, e))


# ---------------------------------------------------------------------------
# acceptance
# ---------------------------------------------------------------------------
def _archive(commit, dest):
    os.makedirs(dest, exist_ok=True)
    tar = subprocess.run(["git", "archive", commit], cwd=REPO,
                         capture_output=True)
    if tar.returncode:
        raise SystemExit("git archive %s failed: %s"
                         % (commit, tar.stderr.decode()[-300:]))
    subprocess.run(["tar", "-x", "-C", dest], input=tar.stdout, check=True)
    return dest


def acceptance():
    fails = []

    def check(name, ok, detail):
        print("  %-10s %-6s %s" % (name, "PASS" if ok else "FAIL", detail))
        if not ok:
            fails.append(name)

    tmp = tempfile.mkdtemp(prefix="r18-accept-")
    try:
        print("archiving %s (last commit before R16) ..." % PRE_R16)
        pre = _archive(PRE_R16, os.path.join(tmp, "pre"))
        print("sweeping the pre-R16 tree with an EMPTY expectations file ...")
        PRE = sweep(pre, {}, "a", verbose=True)
        print("\nsweeping HEAD ...")
        HEAD = sweep(REPO, {}, "a", verbose=True)

        def diverged(blob, b, kind):
            return [q for q in blob["questions"][b]
                    if q["oracle"] == "O1a" and q.get("kind") == kind]

        def ungraded(blob, b, kind):
            return [q for q in blob["questions"][b]
                    if q["oracle"] == "O2" and q.get("kind") == kind
                    and "graded=false" in q["what"]]

        print("\n" + "-" * 78)
        print("ACCEPTANCE - pre-R16 tree (%s), empty expectations file" % PRE_R16)
        b = "hpa-present"
        d = diverged(PRE, b, "ReplicaSet")
        check("AT1", bool(d), "ReplicaSet vs Deployment: %s"
              % (d[0]["what"] if d else "no divergence reported"))
        d = diverged(PRE, b, "Rollout")
        check("AT2", bool(d), "Rollout vs Deployment: %s"
              % (d[0]["what"] if d else "no divergence reported"))
        d = ungraded(PRE, b, "ReplicationController")
        check("AT3", bool(d), "ReplicationController: %s"
              % (d[0]["what"] if d else "graded normally"))

        b2 = "hpa-absent"
        hp = [q for q in PRE["questions"][b2]
              if q["oracle"] == "O2" and q.get("kind") == "DaemonSet"
              and "HP" in q["what"]]
        ds = PRE["tier_a"][b2]["DaemonSet"]["score"]
        dep = PRE["tier_a"][b2]["Deployment"]["score"]
        check("AT4", bool(hp) and ds > dep,
              "DaemonSet, no HPA: HP family silent=%s, score %.1f vs "
              "Deployment %.1f" % (bool(hp), ds, dep))

        bad_a = _self_check()
        check("AT5a", not bad_a, "the oracle contains no answer key%s"
              % ("" if not bad_a else ": " + ", ".join(bad_a)))

        gpath = os.path.join(HERE, "chartgen.py")
        gsrc = open(gpath).read()
        bad_b = [t for t in FORBIDDEN if t in gsrc]
        bad_x = [t for t in FORBIDDEN if t in _executable_tokens(gpath)]
        print("  %-10s %-6s %s"
              % ("AT5b", "FAIL" if bad_b else "PASS",
                 "generator PROSE cites %s - stricter than the criterion the "
                 "design fixed, reported failing rather than erased"
                 % (", ".join(bad_b) or "nothing")))
        check("AT5b-exec", not bad_x,
              "no forbidden name in generator CODE%s"
              % ("" if not bad_x else ": " + ", ".join(bad_x)))

        print("\nACCEPTANCE - HEAD")
        still = [k for k in ("ReplicaSet", "Rollout") if diverged(HEAD, b, k)]
        if ungraded(HEAD, b, "ReplicationController"):
            still.append("ReplicationController")
        check("AT6", not still, "AT1-AT3 no longer reported%s"
              % ("" if not still else "; STILL DIVERGING: " + ", ".join(still)))
        hp_h = [q for q in HEAD["questions"][b2]
                if q["oracle"] == "O2" and q.get("kind") == "DaemonSet"
                and "HP" in q["what"]]
        check("AT7", bool(hp_h),
              "DaemonSet HPA divergence still reported, for dispositioning "
              "as expected (R16 shipped it deliberately)")

        for label, blob in (("pre-R16", PRE), ("HEAD", HEAD)):
            print("  questions %-8s hpa-present %2d, hpa-absent %2d"
                  % (label, len(blob["questions"]["hpa-present"]),
                     len(blob["questions"]["hpa-absent"])))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nACCEPTANCE: %s"
          % ("PASS" if not fails else "FAIL " + ", ".join(fails)))
    return 1 if fails else 0


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=REPO,
                    help="tree to analyze; defaults to this repository")
    ap.add_argument("--expect", default=EXPECT_DEFAULT,
                    help="disposition file; '-' for none (empty)")
    ap.add_argument("--out", default=None, help="write the result blob here")
    ap.add_argument("--tier", default="ab")
    ap.add_argument("--acceptance", action="store_true",
                    help="run AT1-AT7 against %s and HEAD" % PRE_R16)
    a = ap.parse_args()

    if a.acceptance:
        raise SystemExit(acceptance())

    bad = _self_check()
    print("AT5a oracle self-check: %s"
          % ("FAIL - mentions %s" % bad if bad else "PASS - no answer key"))

    expect = {}
    if a.expect and a.expect != "-" and os.path.exists(a.expect):
        with open(a.expect) as fh:
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    k, _, why = ln.partition(" ")
                    expect[k] = why.strip()
    print("dispositions: %s (%d entries)"
          % (os.path.basename(a.expect) if a.expect != "-" else "(none)",
             len(expect)))
    print("tree: %s" % a.repo)

    out = sweep(a.repo, expect, a.tier)
    n_open = sum(1 for b in out["questions"]
                 for q in out["questions"][b] if qkey(q) not in expect)
    print("\n" + "-" * 78)
    print("OPEN QUESTIONS ACROSS ALL BASELINES: %d" % n_open)
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(out, fh, indent=1)
        print("wrote %s" % a.out)
    raise SystemExit(0)


if __name__ == "__main__":
    main()

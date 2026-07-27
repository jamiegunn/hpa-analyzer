"""R18: a Job's probes are not one question, and the tool answered zero of them.

`proof/p20_kindsweep.py` is the instrument that found this, and it argues the
round end to end through the CLI over generated charts. These tests pin the
part a future edit could break silently.

`checks_workload._probes` opened with `if kind in ("job", "cronjob"): return` -
the ninth inline copy of a kind list in this codebase, and the second category
after R16's HPA to be scored 100 for a question nobody asked. Two charts with
BYTE-IDENTICAL container blocks, differing only in `kind` and the
`restartPolicy: Never` the Job schema forces, measured:

    Deployment  92.2  A-  PB004 PB005   Health Probes & Lifecycle  82.0  B-
    Job         94.8  A   (none)        Health Probes & Lifecycle 100.0  A+

The Job is strictly worse - its restartPolicy makes a liveness kill permanent -
and it scored two points higher and its probe category scored a perfect A+
while the SAME REPORT, 200 lines further down, drew a table showing the probe
budget it had just called flawless.

The fix is not "run the probe rules on Jobs". Three of the five genuinely do
not apply, and turning them on would replace a false pass with a false finding.
It is a per-rule split, and the set it turns on is `kube.BATCH_KINDS`, which
answers a FIFTH question none of the four existing sets answer: does this
object RUN TO COMPLETION rather than serving traffic indefinitely?

  PB001 missing readiness   SKIPPED - nothing routes traffic to a Job's pods
  PB002 missing liveness    SKIPPED - a wedged Job's control is
                                      activeDeadlineSeconds, which this tool
                                      does not yet check at all (recorded)
  PB003 liveness == readiness  SKIPPED - follows from the two above
  PB004 startup budget      RUNS - a Job's container still starts a JVM
  PB005 liveness has no startupProbe  RUNS - same

These tests are written as EQUALITY between a batch kind and its non-batch twin
wherever the answer should not depend on the kind, and as an explicit set
difference where it should. Absolute scores are avoided on purpose: the claim
is "a Job is judged on the probes it declared, exactly as a Deployment is", not
"a Job scores 92.7 this week.
"""

import unittest

from hpaanalyzer.engine import analyze
from hpaanalyzer.kube import (BATCH_KINDS, REPLICA_MANAGED_KINDS,
                              SCALABLE_KINDS, SCALE_CANDIDATE_KINDS,
                              UNSCALABLE_KINDS)

from .util import CHART_YAML, make_tree

# One container block, used verbatim for every kind below. A liveness probe
# with a 5s initial delay, a readiness probe, no startupProbe, on a JVM image
# with a heap that needs a real warm-up: the shape PB004 and PB005 exist for.
POD = (
    "      containers:\n"
    "        - name: app\n"
    "          image: eclipse-temurin:21-jre\n"
    "          env:\n"
    "            - name: JAVA_TOOL_OPTIONS\n"
    '              value: "-Xmx6g"\n'
    "          resources:\n"
    "            requests: {cpu: 500m, memory: 8Gi}\n"
    "            limits: {cpu: 500m, memory: 8Gi}\n"
    "          livenessProbe:\n"
    "            httpGet: {path: /healthz, port: 8080}\n"
    "            initialDelaySeconds: 5\n"
    "            periodSeconds: 10\n"
    "          readinessProbe:\n"
    "            httpGet: {path: /ready, port: 8080}\n"
    "            initialDelaySeconds: 5\n"
    "            periodSeconds: 10\n"
)

# The same container with every probe removed. This is what proves the SKIPPED
# rules are still skipped: PB001 and PB002 are "you declared none", so they can
# only be observed on a chart that declares none.
POD_NO_PROBES = (
    "      containers:\n"
    "        - name: app\n"
    "          image: eclipse-temurin:21-jre\n"
    "          env:\n"
    "            - name: JAVA_TOOL_OPTIONS\n"
    '              value: "-Xmx6g"\n'
    "          resources:\n"
    "            requests: {cpu: 500m, memory: 8Gi}\n"
    "            limits: {cpu: 500m, memory: 8Gi}\n"
)

_SEL = ("  selector:\n    matchLabels: {app: t}\n"
        "  template:\n    metadata:\n      labels: {app: t}\n    spec:\n")

# apiVersion + only the spec fields each kind's schema makes mandatory. Every
# difference between these bodies is forced by Kubernetes, not chosen here.
BODIES = {
    "Deployment": ("apps/v1", "  replicas: 3\n" + _SEL),
    "DaemonSet": ("apps/v1", _SEL),
    "Job": ("batch/v1",
            "  template:\n    metadata:\n      labels: {app: t}\n"
            "    spec:\n      restartPolicy: Never\n"),
    "CronJob": ("batch/v1",
                '  schedule: "0 2 * * *"\n'
                "  jobTemplate:\n    spec:\n      template:\n"
                "        metadata:\n          labels: {app: t}\n"
                "        spec:\n          restartPolicy: OnFailure\n"),
}

# The CronJob nests its pod spec two levels deeper, so the container block has
# to be re-indented. It is the same text; only the leading whitespace differs.
_CRON_INDENT = "    "

BATCH = ["Job", "CronJob"]
NOT_BATCH = ["Deployment", "DaemonSet"]

SKIPPED_FOR_BATCH = {"PB001", "PB002", "PB003"}
RUNS_FOR_BATCH = {"PB004", "PB005"}


def chart(kind, pod=POD):
    api, spec = BODIES[kind]
    if kind == "CronJob":
        pod = "".join(_CRON_INDENT + ln if ln.strip() else ln
                      for ln in pod.splitlines(True))
    return make_tree({
        "Chart.yaml": CHART_YAML,
        "values.yaml": "{}\n",
        "templates/w.yaml": (f"apiVersion: {api}\nkind: {kind}\n"
                             f"metadata: {{name: t}}\nspec:\n{spec}{pod}"),
    })


def ids(result):
    return {f.rule_id for f in result.findings}


def pb(result):
    return {r for r in ids(result) if r.startswith("PB")}


class BatchKindsIsAFifthQuestion(unittest.TestCase):
    """If BATCH_KINDS is ever "simplified" into one of the other four sets,
    these fail. Each assertion below names a kind the collapse would move."""

    def test_batch_kinds_is_not_unscalable_kinds(self):
        # UNSCALABLE_KINDS also holds daemonset and pod, both of which serve
        # traffic all day and both of which need a readiness probe.
        self.assertNotIn("daemonset", BATCH_KINDS)
        self.assertIn("daemonset", UNSCALABLE_KINDS)
        self.assertNotIn("pod", BATCH_KINDS)
        self.assertIn("pod", UNSCALABLE_KINDS)

    def test_batch_kinds_is_not_the_complement_of_replica_managed(self):
        # DaemonSet is in neither set. If "not replica managed" had been used
        # as the batch test, a DaemonSet would have lost its probe checks.
        self.assertNotIn("daemonset", REPLICA_MANAGED_KINDS)
        self.assertNotIn("daemonset", BATCH_KINDS)

    def test_batch_kinds_is_not_the_complement_of_scalable(self):
        self.assertNotIn("daemonset", SCALABLE_KINDS)
        self.assertNotIn("daemonset", BATCH_KINDS)

    def test_every_batch_kind_is_a_known_scale_candidate(self):
        # A kind this file has an opinion about must be one the rest of the
        # tool has heard of, or the two lists have drifted again.
        for k in BATCH_KINDS:
            self.assertIn(k, SCALE_CANDIDATE_KINDS)

    def test_every_batch_kind_carries_a_written_reason(self):
        # The point of the dict-with-reasons shape: a kind cannot be added by
        # someone who cannot say why.
        for k, why in BATCH_KINDS.items():
            self.assertTrue(why and len(why) > 30, f"{k} has no real reason")


class ProbesDeclaredAreProbesJudged(unittest.TestCase):
    """The rules that DO apply must not depend on the kind name."""

    def setUp(self):
        self.res = {k: analyze(chart(k)) for k in BATCH + NOT_BATCH}

    def test_startup_budget_rules_fire_on_every_kind(self):
        for k, r in self.res.items():
            self.assertTrue(RUNS_FOR_BATCH <= pb(r),
                            f"{k} is missing {RUNS_FOR_BATCH - pb(r)}")

    def test_a_batch_kind_gets_the_same_probe_verdict_as_a_deployment(self):
        base = pb(self.res["Deployment"])
        for k in BATCH:
            self.assertEqual(pb(self.res[k]), base,
                             f"{k} differs by {pb(self.res[k]) ^ base}")

    def test_the_probe_category_is_not_a_free_hundred_on_a_batch_kind(self):
        # The defect in one line. Before R18 this was 100.0 for Job/CronJob
        # while the identical Deployment scored 82.0.
        from hpaanalyzer.models import Category
        from hpaanalyzer.scoring import category_scores

        def probes(result):
            for cat, score, _f in category_scores(result):
                if cat is Category.PROBES:
                    return score
            raise AssertionError("no PROBES category")

        base = probes(self.res["Deployment"])
        self.assertIsNotNone(base)
        self.assertLess(base, 100.0)
        for k in BATCH:
            self.assertEqual(probes(self.res[k]), base,
                             f"{k}'s PROBES category diverged from Deployment")


class AbsentProbesAreNotHeldAgainstABatchKind(unittest.TestCase):
    """The other half: turning the skip off entirely would be a false finding
    factory, so the three rules that do not apply must stay silent."""

    def setUp(self):
        self.res = {k: analyze(chart(k, pod=POD_NO_PROBES))
                    for k in BATCH + NOT_BATCH}

    def test_a_deployment_with_no_probes_is_told_about_it(self):
        # The control. If this stops firing, the test below proves nothing.
        self.assertTrue(SKIPPED_FOR_BATCH & pb(self.res["Deployment"]),
                        "the control chart raised no missing-probe finding")

    def test_a_daemonset_with_no_probes_is_told_about_it(self):
        # A DaemonSet serves traffic; the fix must not have caught it.
        self.assertTrue(SKIPPED_FOR_BATCH & pb(self.res["DaemonSet"]))

    def test_a_batch_kind_is_not_told_to_add_a_readiness_probe(self):
        for k in BATCH:
            self.assertFalse(SKIPPED_FOR_BATCH & pb(self.res[k]),
                             f"{k} was told to add a probe nothing consumes")


class TheKindListIsNotInlineAnyMore(unittest.TestCase):
    """R17 closed eight inline copies and R18 found the ninth. This is the
    cheap check that stops the tenth appearing in the same file."""

    # THE FIRST VERSION OF THIS TEST WAS WRONG AND THE RUN PROVED IT. It
    # grepped `inspect.getsource(checks_workload)` for the literal tuple and
    # FAILED - because `_probes`'s new docstring QUOTES the line it deleted,
    # which is the whole point of the docstring. A check that cannot tell code
    # from the documentation of removed code would, if satisfied, have forced
    # the deletion of the only record of what was fixed. Recorded here rather
    # than silently rewritten; the version below tokenizes and looks at
    # executable code only, which is what was meant.

    @staticmethod
    def _executable_source(module):
        import io
        import inspect
        import token
        import tokenize
        src = inspect.getsource(module)
        out, prev = [], token.INDENT
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                continue
            # a STRING alone on a logical line is a docstring, not a value
            if (tok.type == tokenize.STRING
                    and prev in (token.INDENT, token.DEDENT, token.NEWLINE,
                                 tokenize.NL, tokenize.ENCODING)):
                prev = tok.type
                continue
            if tok.type not in (tokenize.NL, tokenize.NEWLINE,
                                token.INDENT, token.DEDENT):
                prev = tok.type
            else:
                prev = tok.type
                continue
            out.append(tok.string)
        return " ".join(out)

    def test_checks_workload_does_not_re_type_the_batch_kind_list(self):
        from hpaanalyzer import checks_workload
        src = self._executable_source(checks_workload)
        # The two kind names, as string literals, adjacent in executable code.
        # Written by joining so this test does not itself become the tenth copy
        # for a future grep to find.
        needle = '"' + "job" + '" , "' + "cronjob" + '"'
        self.assertNotIn(needle, src,
                         "the inline kind tuple is back in checks_workload")

    def test_that_check_can_still_see_a_real_regression(self):
        # The control for the test above. A tokenizer that dropped too much
        # would make it pass on anything; this proves it still finds the
        # pattern in code, and still ignores it in a docstring.
        import types
        m = types.ModuleType("m")
        m.__file__ = "<m>"
        good = 'def f(kind):\n    """if kind in ("job", "cronjob"): return"""\n    return kind\n'
        bad = 'def f(kind):\n    if kind in ("job", "cronjob"):\n        return\n'
        needle = '"' + "job" + '" , "' + "cronjob" + '"'
        import inspect
        import unittest.mock as mock
        for src, expected in ((good, False), (bad, True)):
            with mock.patch.object(inspect, "getsource", lambda _m, s=src: s):
                self.assertEqual(needle in self._executable_source(m), expected)


if __name__ == "__main__":
    unittest.main()

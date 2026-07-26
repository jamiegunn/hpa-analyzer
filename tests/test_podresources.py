"""Conformance suite for the pod resource footprint (contract C1.5).

Authority, fetched not recalled:

  aggregateContainerResourcesByFn
      kubernetes/staging/src/k8s.io/component-helpers/resource/helpers.go
  KEP-753 sidecar-containers, "Resources calculation for scheduling and pod
  admission" / "Exposing Pod Resource Requirements"

The rule that is easy to get wrong, and that this suite exists to pin:

    InitContainerUse(i) = sum(restartable init containers with index < i)
                          + resources of the i-th init container

so a one-shot init container is max'd against the SIDECARS ALREADY RUNNING
beside it, not against zero, and not against the regular containers (which
have not started yet). Declaration ORDER changes the answer.
"""

import unittest

from hpaanalyzer.podresources import pod_resources, pods_per_node

MiB = 1024 ** 2
GiB = 1024 ** 3


def _c(name, cpu=None, mem=None, lcpu=None, lmem=None, **kw):
    req, lim = {}, {}
    if cpu:
        req["cpu"] = cpu
    if mem:
        req["memory"] = mem
    if lcpu:
        lim["cpu"] = lcpu
    if lmem:
        lim["memory"] = lmem
    res = {}
    if req:
        res["requests"] = req
    if lim:
        res["limits"] = lim
    c = {"name": name, "resources": res}
    c.update(kw)
    return c


def _pod(containers=(), init=(), **kw):
    ps = {"containers": list(containers)}
    if init:
        ps["initContainers"] = list(init)
    ps.update(kw)
    return ps


class TestRegularContainers(unittest.TestCase):
    def test_regular_containers_are_summed(self):
        pr = pod_resources(_pod([_c("app", "1", "2Gi"), _c("proxy", "100m", "128Mi")]))
        self.assertEqual(pr.requests["cpu"], 1100)
        self.assertEqual(pr.requests["memory"], 2048 * MiB + 128 * MiB)

    def test_a_container_with_no_resources_contributes_zero(self):
        pr = pod_resources(_pod([_c("app", "1", "2Gi"), _c("bare")]))
        self.assertEqual(pr.requests["cpu"], 1000)

    def test_missing_limits_are_flagged_not_summed_as_a_cap(self):
        # summing limits where one container has none produces a number that
        # looks like a ceiling and is not one.
        pr = pod_resources(_pod([_c("app", "1", "2Gi", "1", "2Gi"), _c("bare")]))
        self.assertFalse(pr.limits_complete)


class TestNativeSidecars(unittest.TestCase):
    """restartPolicy: Always on an init container -> summed, like a regular
    container, because it runs for the pod's entire life (GA 1.33)."""

    def test_sidecar_is_summed_not_maxed(self):
        pr = pod_resources(_pod(
            [_c("app", "1", "2Gi")],
            init=[_c("log-shipper", "50m", "128Mi", restartPolicy="Always")]))
        self.assertEqual(pr.requests["cpu"], 1050)
        self.assertEqual(pr.requests["memory"], 2048 * MiB + 128 * MiB)

    def test_a_sidecar_is_not_the_same_thing_as_an_init_container(self):
        side = pod_resources(_pod(
            [_c("app", "1", "2Gi")],
            init=[_c("x", "500m", "1Gi", restartPolicy="Always")]))
        oneshot = pod_resources(_pod(
            [_c("app", "1", "2Gi")], init=[_c("x", "500m", "1Gi")]))
        self.assertEqual(side.requests["cpu"], 1500)     # summed
        self.assertEqual(oneshot.requests["cpu"], 1000)  # max(1000, 500)

    def test_sidecar_kind_is_labelled(self):
        pr = pod_resources(_pod(
            [_c("app", "1", "2Gi")],
            init=[_c("boot"), _c("side", restartPolicy="Always")]))
        kinds = {s.name: s.kind for s in pr.shares}
        self.assertEqual(kinds["app"], "container")
        self.assertEqual(kinds["boot"], "init")
        self.assertEqual(kinds["side"], "sidecar")


class TestOneShotInitContainers(unittest.TestCase):
    def test_small_init_is_absorbed(self):
        pr = pod_resources(_pod([_c("app", "1", "2Gi")],
                                init=[_c("wait", "10m", "32Mi")]))
        self.assertEqual(pr.requests["cpu"], 1000)
        self.assertFalse(pr.init_dominates)

    def test_large_init_sets_the_bar_the_node_must_clear(self):
        # a migration job that needs 8Gi for 30s still needs a node with 8Gi.
        pr = pod_resources(_pod([_c("app", "500m", "1Gi")],
                                init=[_c("migrate", "2", "8Gi")]))
        self.assertEqual(pr.requests["memory"], 8 * GiB)
        self.assertEqual(pr.requests["cpu"], 2000)
        self.assertTrue(pr.init_dominates)
        # ... but the steady state is still the smaller number, and the report
        # must be able to tell the user both.
        self.assertEqual(pr.steady["memory"], 1 * GiB)

    def test_per_resource_max_not_whole_vector_max(self):
        # cpu comes from the init container, memory from the steady state.
        pr = pod_resources(_pod([_c("app", "500m", "4Gi")],
                                init=[_c("migrate", "4", "1Gi")]))
        self.assertEqual(pr.requests["cpu"], 4000)
        self.assertEqual(pr.requests["memory"], 4 * GiB)

    def test_init_is_maxed_against_sidecars_declared_before_it(self):
        # THE case the KEP formula exists for. The sidecar is already running
        # while the one-shot init container runs, so the startup peak is
        # 1Gi (sidecar) + 4Gi (init) = 5Gi, which exceeds the 3Gi steady
        # state and therefore decides the pod's request.
        pr = pod_resources(_pod(
            [_c("app", "1", "2Gi")],
            init=[_c("side", "500m", "1Gi", restartPolicy="Always"),
                  _c("migrate", "1", "4Gi")]))
        self.assertEqual(pr.steady["memory"], 3 * GiB)
        self.assertEqual(pr.init_peak["memory"], 5 * GiB)
        self.assertEqual(pr.requests["memory"], 5 * GiB)

    def test_declaration_order_changes_the_answer(self):
        # same containers, sidecar declared AFTER the init container: the
        # sidecar is not running yet, so the peak is 4Gi, and the steady
        # state (3Gi) does not exceed it either -> 4Gi, not 5Gi.
        after = pod_resources(_pod(
            [_c("app", "1", "2Gi")],
            init=[_c("migrate", "1", "4Gi"),
                  _c("side", "500m", "1Gi", restartPolicy="Always")]))
        self.assertEqual(after.init_peak["memory"], 4 * GiB)
        self.assertEqual(after.requests["memory"], 4 * GiB)

    def test_two_one_shot_inits_do_not_sum_with_each_other(self):
        pr = pod_resources(_pod([_c("app", "100m", "256Mi")],
                                init=[_c("a", "1", "2Gi"), _c("b", "1", "3Gi")]))
        self.assertEqual(pr.requests["memory"], 3 * GiB)   # max, not 5Gi


class TestPodLevelAndOverhead(unittest.TestCase):
    def test_pod_level_resources_override_the_aggregate(self):
        pr = pod_resources(_pod([_c("app", "1", "2Gi")],
                                resources={"requests": {"cpu": "4", "memory": "8Gi"}}))
        self.assertTrue(pr.pod_level)
        self.assertEqual(pr.requests["cpu"], 4000)
        self.assertEqual(pr.requests["memory"], 8 * GiB)

    def test_overhead_is_added(self):
        # RuntimeClass overhead (e.g. Kata) is charged to the node and appears
        # in no container's spec at all.
        pr = pod_resources(_pod([_c("app", "1", "2Gi")],
                                overhead={"cpu": "250m", "memory": "120Mi"}))
        self.assertEqual(pr.requests["cpu"], 1250)
        self.assertEqual(pr.requests["memory"], 2048 * MiB + 120 * MiB)


class TestUndetermined(unittest.TestCase):
    """C2.2: a container whose quantity will not resolve must not silently
    contribute zero to a total."""

    def test_unresolved_template_makes_the_total_undetermined(self):
        pr = pod_resources(_pod([_c("app", "{{ .Values.cpu }}", "2Gi")]))
        self.assertFalse(pr.decided)
        self.assertTrue(any("app.requests.cpu" in u for u in pr.undetermined))

    def test_a_resolvable_pod_is_decided(self):
        self.assertTrue(pod_resources(_pod([_c("app", "1", "2Gi")])).decided)


class TestTheDeclaredFlag(unittest.TestCase):
    """`declared` records something the arithmetic deliberately cannot see.

    To the scheduler, "no resources block" and "a resources block with limits
    and no requests" are the same number: zero requested. The model must keep
    treating them as the same number - that is Bar 1, and the first test here
    pins it. But they are not the same mistake by the author: one container
    was never sized, the other was sized and the request half was forgotten,
    with a limit already bounding the damage. RS017 grades those differently
    (CRITICAL vs HIGH), so the flag has to be right, and it has to be right
    for all three container kinds - a blind sidecar living in initContainers
    is precisely the case that motivated it.
    """

    def _by_name(self, pr):
        return {s.name: s.declared for s in pr.shares}

    def test_the_flag_does_not_change_any_total(self):
        # The flag is metadata about intent. If it ever leaks into the
        # arithmetic, this fails.
        bare = pod_resources(_pod([_c("app", "1", "2Gi"), _c("bare")]))
        limits_only = pod_resources(_pod([_c("app", "1", "2Gi"),
                                          _c("bare", lcpu="1", lmem="1Gi")]))
        self.assertEqual(bare.requests, limits_only.requests)
        self.assertFalse(self._by_name(bare)["bare"])
        self.assertTrue(self._by_name(limits_only)["bare"])

    def test_a_populated_block_is_declared(self):
        pr = pod_resources(_pod([_c("app", "1", "2Gi")]))
        self.assertTrue(self._by_name(pr)["app"])

    def test_an_empty_block_is_not_declared(self):
        # resources: {} is what a chart renders when values.yaml has an empty
        # `resources:` key - the commonest way to ship an unsized container.
        pr = pod_resources(_pod([{"name": "app", "resources": {}}]))
        self.assertFalse(self._by_name(pr)["app"])

    def test_a_missing_block_is_not_declared(self):
        pr = pod_resources(_pod([{"name": "app"}]))
        self.assertFalse(self._by_name(pr)["app"])

    def test_requests_alone_or_limits_alone_both_count_as_declared(self):
        pr = pod_resources(_pod([_c("reqonly", "1", "2Gi"),
                                 _c("limonly", lcpu="1", lmem="2Gi")]))
        self.assertEqual(self._by_name(pr),
                         {"reqonly": True, "limonly": True})

    def test_the_flag_is_set_for_sidecars_and_init_containers_too(self):
        pr = pod_resources(_pod(
            [_c("app", "1", "2Gi")],
            init=[_c("blind-side", restartPolicy="Always"),
                  _c("sized-side", "50m", "64Mi", restartPolicy="Always"),
                  _c("blind-init"),
                  _c("sized-init", "500m", "1Gi")]))
        self.assertEqual(
            self._by_name(pr),
            {"app": True, "blind-side": False, "sized-side": True,
             "blind-init": False, "sized-init": True})

    def test_a_malformed_resources_value_is_not_declared(self):
        # `resources: "small"` is a chart bug, not a declaration. Reading it
        # as one would make the tool report a sizing mistake it cannot see.
        pr = pod_resources(_pod([{"name": "app", "resources": "small"}]))
        self.assertFalse(self._by_name(pr)["app"])


class TestPodsPerNode(unittest.TestCase):
    def test_uses_the_pod_request(self):
        self.assertEqual(pods_per_node(2304 * MiB, 8 * GiB), 3)

    def test_zero_request_is_none_not_infinity(self):
        # a BestEffort pod is not bounded by memory request; inventing a
        # number here would be exactly the C2.2 failure.
        self.assertIsNone(pods_per_node(0, 8 * GiB))
        self.assertIsNone(pods_per_node(None, 8 * GiB))


class TestAgainstTheShippedFixture(unittest.TestCase):
    """The numbers proof/p2_sidecar.py derived independently."""

    def test_sidecar_chart_totals(self):
        import os

        from hpaanalyzer.engine import analyze
        from hpaanalyzer.kube import pod_spec
        root = os.path.join(os.path.dirname(__file__), "..", "fixtures",
                            "sidecar-chart")
        r = analyze(root, helm_mode="off")
        pr = pod_resources(pod_spec(r.context.workloads[0]))
        self.assertEqual(pr.requests["cpu"], 1150)
        self.assertEqual(pr.requests["memory"], 2304 * MiB)
        self.assertEqual(pods_per_node(pr.requests["memory"], 8 * GiB), 3)
        self.assertEqual([s.name for s in pr.sidecars()], ["log-shipper"])


if __name__ == "__main__":
    unittest.main()

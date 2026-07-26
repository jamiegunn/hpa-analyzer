"""Conformance suite for pod QoS (contract C1.1-C1.5).

Every case below is justified by upstream source, not by intuition:

  ComputePodQOS / requirementsQOS / resourceQOS
      kubernetes/pkg/apis/core/v1/helper/qos/qos.go
  SetDefaults_Pod (requests default to limits, containers AND initContainers)
      kubernetes/pkg/apis/core/v1/defaults.go

The predecessor of hpaanalyzer.qos classified QoS per CONTAINER and printed it
under a pod-level heading. It failed cases A, B, C, D and H below - two of
which are single-container pods, which is why "exact for single-container
workloads" was not a valid defence.
"""

import unittest

from hpaanalyzer.qos import (BESTEFFORT, BURSTABLE, GUARANTEED, UNKNOWN,
                             pod_qos, requirements_qos)


def _c(name, req=None, lim=None, **kw):
    res = {}
    if req:
        res["requests"] = req
    if lim:
        res["limits"] = lim
    c = {"name": name, "resources": res}
    c.update(kw)
    return c


def _pod(containers=(), init=(), pod_resources=None):
    ps = {"containers": list(containers)}
    if init:
        ps["initContainers"] = list(init)
    if pod_resources:
        ps["resources"] = pod_resources
    return ps


G = {"cpu": "1", "memory": "1Gi"}


class TestUpstreamConformance(unittest.TestCase):
    """(id, pod spec, expected class, upstream justification)"""

    CASES = [
        ("A. limits only, no requests block", _pod([_c("app", lim=G)]),
         GUARANTEED,
         "SetDefaults_Pod copies each limit into requests; req==lim!=0 for "
         "cpu and memory -> Guaranteed"),

        ("B. Guaranteed app + Burstable sidecar",
         _pod([_c("app", G, G), _c("istio-proxy", {"cpu": "10m"})]),
         BURSTABLE,
         "requestsQOS(istio-proxy): cpu req!=lim -> Burstable; ComputePodQOS "
         "returns on the first Burstable container"),

        ("C. Guaranteed app + container with no resources at all",
         _pod([_c("app", G, G), _c("log-shipper")]),
         BURSTABLE,
         "one Guaranteed + one BestEffort -> classes differ -> Burstable"),

        ("D. Guaranteed app + BestEffort INIT container",
         _pod([_c("app", G, G)], init=[_c("wait-for-db")]),
         BURSTABLE,
         "the container iterator yields InitContainers before Containers"),

        ("E. cpu req==lim, memory req<lim",
         _pod([_c("app", {"cpu": "1", "memory": "512Mi"}, G)]),
         BURSTABLE,
         "resourceQOS(memory) -> Burstable short-circuits requirementsQOS"),

        ("F. memory req==lim, cpu absent entirely",
         _pod([_c("app", {"memory": "1Gi"}, {"memory": "1Gi"})]),
         BURSTABLE,
         "cpu -> BestEffort, memory -> Guaranteed, mismatch -> Burstable"),

        ("G. nothing set anywhere", _pod([_c("app")]), BESTEFFORT,
         "len(Requests)==0 and len(Limits)==0 -> BestEffort"),

        ("H. explicit zero quantities",
         _pod([_c("app", {"cpu": "0", "memory": "0"}, {"cpu": "0", "memory": "0"})]),
         BESTEFFORT,
         "resourceQOS: req==lim and IsZero -> BestEffort (NOT Guaranteed)"),

        ("I. native sidecar (init w/ restartPolicy: Always) Burstable",
         _pod([_c("app", G, G)],
              init=[_c("proxy", {"cpu": "10m"}, {"cpu": "100m"},
                       restartPolicy="Always")]),
         BURSTABLE,
         "native sidecars are initContainers and are iterated for QoS"),

        ("J. every container Guaranteed, including init",
         _pod([_c("app", G, G), _c("side", G, G)], init=[_c("boot", G, G)]),
         GUARANTEED,
         "every container yields Guaranteed, so podQOS never diverges and no "
         "Burstable early-out fires"),

        ("K. all containers BestEffort", _pod([_c("a"), _c("b")]), BESTEFFORT,
         "requirementsQOS returns BestEffort for each; classes agree so the "
         "pod keeps that class rather than falling through to Burstable"),

        ("L. limits only on ONE resource",
         _pod([_c("app", lim={"memory": "1Gi"})]), BURSTABLE,
         "memory defaults req=lim -> Guaranteed; cpu unset -> BestEffort; "
         "mismatch -> Burstable"),

        ("M. request > limit (invalid, but QoS is still defined)",
         _pod([_c("app", {"cpu": "2", "memory": "2Gi"}, G)]), BURSTABLE,
         "req != lim -> Burstable regardless of direction"),

        ("N. equal values written with different units",
         _pod([_c("app", {"cpu": "1000m", "memory": "1024Mi"},
                  {"cpu": "1", "memory": "1Gi"})]),
         GUARANTEED,
         "quantities compare by value, not by string: 1000m == 1, 1024Mi == 1Gi"),

        ("O. pod-level resources decide (PodLevelResources, beta 1.34)",
         _pod([_c("app", {"cpu": "10m"})], pod_resources={"requests": G, "limits": G}),
         GUARANTEED,
         "ComputePodQOS returns requirementsQOS(pod.Spec.Resources) and never "
         "reaches the container loop"),

        ("P. no containers at all", _pod([]), BESTEFFORT,
         "podQOS == '' after the loop -> BestEffort"),
    ]

    def test_conformance_table(self):
        failures = []
        for cid, spec, expected, why in self.CASES:
            got = pod_qos(spec).qos
            if got != expected:
                failures.append(f"{cid}: expected {expected}, got {got} ({why})")
        self.assertFalse(failures, "\n" + "\n".join(failures))

    def test_every_case_has_a_justification(self):
        # C2.x discipline: a case with no upstream justification is a guess.
        for cid, _spec, _exp, why in self.CASES:
            self.assertTrue(len(why) > 20, f"{cid} lacks a justification")


class TestUndetermined(unittest.TestCase):
    """C2.2: an unresolvable quantity yields Unknown, never a guess."""

    def test_unparseable_request_is_unknown(self):
        pq = pod_qos(_pod([_c("app", {"cpu": "{{ .Values.cpu }}", "memory": "1Gi"},
                              {"cpu": "1", "memory": "1Gi"})]))
        self.assertEqual(pq.qos, UNKNOWN)
        self.assertFalse(pq.decided)
        self.assertIn("unresolved", pq.reason.lower())

    def test_decided_burstable_beats_unknown_sibling(self):
        # upstream short-circuits on the first Burstable container; an
        # undecidable *other* container cannot change that answer.
        pq = pod_qos(_pod([_c("app", {"cpu": "100m"}, {"cpu": "1", "memory": "1Gi"}),
                           _c("x", {"cpu": "HELMVAL@foo"})]))
        self.assertEqual(pq.qos, BURSTABLE)

    def test_unknown_does_not_masquerade_as_besteffort(self):
        pq = pod_qos(_pod([_c("app", {"memory": "{{ tpl }}"}, {"memory": "{{ tpl }}"})]))
        self.assertEqual(pq.qos, UNKNOWN)


class TestReasonsAndDetails(unittest.TestCase):
    def test_reason_names_the_deciding_container(self):
        pq = pod_qos(_pod([_c("app", G, G), _c("istio-proxy", {"cpu": "10m"})]))
        self.assertIn("istio-proxy", pq.reason)

    def test_init_container_role_is_labelled(self):
        pq = pod_qos(_pod([_c("app", G, G)],
                          init=[_c("boot"), _c("proxy", restartPolicy="Always")]))
        roles = {d.name: d.kind for d in pq.containers}
        self.assertEqual(roles["boot"], "init")
        self.assertEqual(roles["proxy"], "sidecar")
        self.assertEqual(roles["app"], "container")

    def test_defaulted_requests_are_recorded(self):
        pq = pod_qos(_pod([_c("app", lim=G)]))
        self.assertEqual(sorted(pq.containers[0].defaulted), ["cpu", "memory"])

    def test_pod_level_flagged(self):
        pq = pod_qos(_pod([_c("app")], pod_resources={"requests": G, "limits": G}))
        self.assertTrue(pq.pod_level)


class TestRequirementsQos(unittest.TestCase):
    def test_absent_section_is_besteffort(self):
        self.assertEqual(requirements_qos(None)[0], BESTEFFORT)
        self.assertEqual(requirements_qos({})[0], BESTEFFORT)

    def test_non_qos_resources_are_ignored(self):
        # only cpu and memory are supportedQoSComputeResources upstream
        q, _, _, _ = requirements_qos({"requests": {"ephemeral-storage": "1Gi"},
                                       "limits": {"ephemeral-storage": "1Gi"}})
        self.assertEqual(q, BESTEFFORT)

    def test_hugepages_do_not_make_it_guaranteed(self):
        q, _, _, _ = requirements_qos({"requests": {"hugepages-2Mi": "1Gi"},
                                       "limits": {"hugepages-2Mi": "1Gi"}})
        self.assertEqual(q, BESTEFFORT)


if __name__ == "__main__":
    unittest.main()

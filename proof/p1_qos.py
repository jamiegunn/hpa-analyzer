"""PROOF R1: pod QoS, before vs after.

Ground truth: k8s master pkg/apis/core/v1/helper/qos/qos.go (ComputePodQOS)
              + pkg/apis/core/v1/defaults.go (SetDefaults_Pod).

OLD column = behaviour of the shipped per-container qos_class(), measured on
2026-07-26 before the fix (that function has since been deleted; its outputs
are recorded here verbatim from the measurement run).
"""
import os
import sys
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from hpaanalyzer.qos import pod_qos

C = lambda n, rq=None, lm=None, **k: dict({"name": n, "resources":
        ({"requests": rq} if rq else {}) | ({"limits": lm} if lm else {})}, **k)
G = {"cpu": "1", "memory": "1Gi"}

CASES = [
 ("A single container, LIMITS ONLY", {"containers":[C("app",lm=G)]}, "Guaranteed", "Burstable"),
 ("B Guaranteed app + Burstable istio-proxy", {"containers":[C("app",G,G),C("istio-proxy",{"cpu":"10m"})]}, "Burstable", "Guaranteed (app row)"),
 ("C Guaranteed app + resource-less sidecar", {"containers":[C("app",G,G),C("log-shipper")]}, "Burstable", "Guaranteed (app row)"),
 ("D Guaranteed app + BestEffort init", {"containers":[C("app",G,G)],"initContainers":[C("wait-for-db")]}, "Burstable", "Guaranteed (init invisible)"),
 ("E cpu req==lim, mem req<lim", {"containers":[C("app",{"cpu":"1","memory":"512Mi"},G)]}, "Burstable", "Burstable"),
 ("F memory only, no cpu", {"containers":[C("app",{"memory":"1Gi"},{"memory":"1Gi"})]}, "Burstable", "Burstable"),
 ("G nothing set", {"containers":[C("app")]}, "BestEffort", "BestEffort"),
 ("H explicit zeros", {"containers":[C("app",{"cpu":"0","memory":"0"},{"cpu":"0","memory":"0"})]}, "BestEffort", "Guaranteed"),
]
print(f"{'case':<44}{'k8s truth':<12}{'OLD (per-container)':<30}{'NEW (pod_qos)':<12} verdict")
print("-"*116)
old_bad = new_bad = 0
for t, spec, truth, old in CASES:
    new = pod_qos(spec).qos
    ok_old = old == truth
    ok_new = new == truth
    old_bad += not ok_old; new_bad += not ok_new
    print(f"{t:<44}{truth:<12}{old+('  OK' if ok_old else '  WRONG'):<30}{new:<12} {'PASS' if ok_new else 'FAIL'}")
print("-"*116)
print(f"OLD: {old_bad}/{len(CASES)} wrong.   NEW: {new_bad}/{len(CASES)} wrong.")
sys.exit(1 if new_bad else 0)

"""kube.py helper contracts: pod-spec extraction, JVM evidence, coercions.

Everything here is pure functions over ManifestDoc/dict inputs - the same
shapes discovery hands the checks - so the tests feed them literal documents
and assert on the answers.
"""

import unittest

from hpaanalyzer import kube
from hpaanalyzer.dockerparse import parse_dockerfile
from hpaanalyzer.models import ChartContext, ManifestDoc


def doc(kind, data):
    return ManifestDoc(file="t.yaml", kind=kind, api_version="v1", data=data)


def deployment_with_containers(containers):
    return doc("Deployment",
               {"spec": {"template": {"spec": {"containers": containers}}}})


class TestPodSpec(unittest.TestCase):
    def test_non_dict_spec_yields_none(self):
        # In static mode `spec:` can scrub to a bare marker string; that is
        # "no pod spec here", not a crash.
        self.assertIsNone(kube.pod_spec(doc("Deployment", {"spec": "HELMTPL"})))

    def test_bare_pod_spec_is_the_pod_spec(self):
        # A Pod has no template indirection: its spec IS the pod spec.
        ps = kube.pod_spec(doc("Pod", {"spec": {"containers": []}}))
        self.assertEqual(ps, {"containers": []})

    def test_workload_without_template_yields_none(self):
        # A Deployment's containers live only under spec.template.spec; a
        # Deployment missing it has no pod spec, and must not fall back to
        # returning its own spec the way a Pod does.
        self.assertIsNone(kube.pod_spec(doc("Deployment", {"spec": {"x": 1}})))

    def test_cronjob_without_jobtemplate_yields_none(self):
        self.assertIsNone(kube.pod_spec(doc("CronJob", {"spec": {"x": 1}})))


class TestDocName(unittest.TestCase):
    def test_missing_metadata_is_unnamed(self):
        self.assertEqual(kube.doc_name(doc("ConfigMap", {"spec": {}})), "(unnamed)")

    def test_non_dict_metadata_is_unnamed(self):
        self.assertEqual(kube.doc_name(doc("ConfigMap", {"metadata": "x"})),
                         "(unnamed)")


class TestAsInt(unittest.TestCase):
    def test_bool_is_not_an_int(self):
        # bool subclasses int in Python; `minReplicas: true` must not be
        # silently read as 1.
        self.assertIsNone(kube.as_int(True))
        self.assertIsNone(kube.as_int(False))

    def test_quoted_integer_coerces(self):
        self.assertEqual(kube.as_int("6"), 6)
        self.assertEqual(kube.as_int(6), 6)
        self.assertIsNone(kube.as_int("6.5"))


class TestJvmEnvFlags(unittest.TestCase):
    def test_value_from_entries_contribute_no_flags(self):
        # JAVA_TOOL_OPTIONS via valueFrom has no literal value to read flags
        # from; the parser must skip it and still read the literal sibling.
        c = {"name": "app", "image": "repo/app:1", "env": [
            {"name": "JAVA_TOOL_OPTIONS", "valueFrom": {"configMapKeyRef": {}}},
            {"name": "JAVA_TOOL_OPTIONS", "value": "-Xmx512m"},
        ]}
        self.assertEqual(kube.container_jvm_env_flags(c), ["-Xmx512m"])

    def test_flag_source_names_the_env_var_only_when_the_flag_is_there(self):
        c = {"name": "app", "image": "repo/app:1", "env": [
            {"name": "JAVA_TOOL_OPTIONS", "value": "no flags in here"},
            {"name": "JDK_JAVA_OPTIONS", "value": "-Xmx512m"},
        ]}
        self.assertEqual(kube.container_jvm_env_flag_source(c, "Xmx"),
                         "JDK_JAVA_OPTIONS")
        # Asking for a flag nobody set is None - provenance is never invented.
        self.assertIsNone(kube.container_jvm_env_flag_source(c, "-Xms"))


class TestContainerJvmEvidence(unittest.TestCase):
    def test_plain_env_and_image_is_no_evidence(self):
        c = {"name": "web", "image": "nginx:1.25", "env": [
            {"name": "PATH", "value": "/bin"},
            {"name": "LOG_LEVEL", "value": "info"},
        ]}
        self.assertIsNone(kube.container_jvm_evidence(c))

    def test_hint_env_var_is_evidence_without_flags(self):
        # CATALINA_OPTS is not auto-read by the JVM (contributes no flags),
        # but only a Java workload sets it - it answers "is this Java" while
        # leaving "configured how" unanswered, which is exactly the
        # distinction the evidence text records.
        c = {"name": "tc", "image": "corp/opaque:1",
             "env": [{"name": "CATALINA_OPTS", "value": "-q"}]}
        ev = kube.container_jvm_evidence(c)
        self.assertIn("CATALINA_OPTS", ev)
        self.assertIn("only a JVM workload has", ev)


class TestDockerfileJvmEvidence(unittest.TestCase):
    def test_none_dockerfile_is_no_evidence(self):
        self.assertIsNone(kube.dockerfile_jvm_evidence(None))

    def test_jvm_flags_without_a_java_base_are_evidence(self):
        # No Java base image, but the ENV sets real JVM flags: the workload is
        # a JVM even though the version cannot be read from the FROM line.
        df = parse_dockerfile(
            "Dockerfile",
            'FROM alpine:3.19\nENV JAVA_TOOL_OPTIONS="-Xmx512m -XX:+UseG1GC"\n')
        self.assertIsNone(df.java_major)
        ev = kube.dockerfile_jvm_evidence(df)
        self.assertIn("sets JVM flags", ev)
        self.assertIn("-Xmx512m", ev)

    def test_java_opt_var_without_flags_is_still_evidence(self):
        # JAVA_OPTS defined but carrying no parseable flag: defining the
        # variable at all is the author saying "a JVM reads this".
        df = parse_dockerfile(
            "Dockerfile", 'FROM alpine:3.19\nENV JAVA_OPTS="see launcher"\n')
        self.assertEqual(df.jvm_flags, [])
        self.assertIn("defines JAVA_OPTS", kube.dockerfile_jvm_evidence(df))

    def test_non_java_entrypoint_is_no_evidence(self):
        df = parse_dockerfile(
            "Dockerfile",
            'FROM alpine:3.19\nENTRYPOINT ["/bin/sh", "-c", "serve"]\n')
        self.assertIsNone(kube.dockerfile_jvm_evidence(df))

    def test_java_entrypoint_is_evidence_even_from_scratch(self):
        df = parse_dockerfile(
            "Dockerfile", 'FROM scratch\nENTRYPOINT ["/opt/java", "-jar", "a.jar"]\n')
        self.assertIn("entrypoint runs `java`", kube.dockerfile_jvm_evidence(df))


class TestThisContainerIsJvm(unittest.TestCase):
    def test_non_jvm_dockerfile_lends_no_evidence(self):
        # A chart-level Dockerfile only vouches for a container when the
        # Dockerfile itself shows a JVM; a shell-entrypoint alpine image does
        # not, so a plain container stays non-JVM.
        df = parse_dockerfile(
            "Dockerfile", 'FROM alpine:3.19\nENTRYPOINT ["/bin/sh", "-c", "x"]\n')
        ctx = ChartContext(dockerfiles=[df])
        self.assertIsNone(kube.this_container_is_jvm(
            ctx, {"name": "app", "image": "repo/app:1"}))


class TestEmptyValuesResourcesReach(unittest.TestCase):
    def test_values_templated_resources_do_consume_the_key(self):
        # A container whose resources block is still a HELMVAL@ marker was
        # templated from values - an empty `resources: {}` in values really
        # lands on this pod, so VA004's inference holds.
        ctx = ChartContext(docs=[deployment_with_containers(
            [{"name": "app", "image": "r/a:1", "resources": "HELMVAL@resources"}])])
        self.assertTrue(kube.empty_values_resources_reach_a_container(ctx))

    def test_helper_supplied_resources_do_not(self):
        # HELMINC@ means the block comes from a named template the static
        # parser never expands: the empty values key is dead weight there,
        # and VA004 must stay silent.
        ctx = ChartContext(docs=[deployment_with_containers(
            [{"name": "app", "image": "r/a:1", "resources": "HELMINC@t.res"}])])
        self.assertFalse(kube.empty_values_resources_reach_a_container(ctx))


if __name__ == "__main__":
    unittest.main()

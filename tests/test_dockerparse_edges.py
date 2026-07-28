"""Dockerfile parsing edges: exotic-but-real constructs the main suite skips.

Each test is a claim about what the parser is allowed to conclude from a
Dockerfile shape - in particular, when it must conclude NOTHING (a nonsense
version tag, a bare instruction word) rather than fabricate a Java version
that every downstream JV rule would then reason from.
"""

import unittest

from hpaanalyzer.dockerparse import (effective_flags, inert_opt_vars,
                                     parse_dockerfile)


def parse(text):
    return parse_dockerfile("Dockerfile", text)


class TestJavaDetectionEdges(unittest.TestCase):
    def test_distroless_without_tag_reads_major_from_image_name(self):
        # gcr.io distroless images carry the major in the NAME, not the tag;
        # the empty tag must not stop detection (or crash the tag parser).
        df = parse("FROM gcr.io/distroless/java17-debian12\n")
        self.assertEqual(df.java_major, 17)
        self.assertIsNone(df.java_update)

    def test_ubi_openjdk_reads_major_from_image_name(self):
        df = parse("FROM registry.access.redhat.com/ubi8/openjdk-17:1.18\n")
        self.assertEqual(df.java_major, 17)

    def test_app_style_tag_on_a_jvm_repo_is_not_a_java_version(self):
        # graalvm community images shipped tags like 1.0.0-rc16; '1' is not a
        # plausible Java major and must not become one.
        df = parse("FROM ghcr.io/graalvm/graalvm-ce:1.0.0-rc16\n")
        self.assertIsNone(df.java_major)
        self.assertIsNone(df.java_update)

    def test_out_of_range_numeric_tag_is_not_a_java_version(self):
        df = parse("FROM openjdk:99-ea\n")
        self.assertIsNone(df.java_major)

    def test_no_from_at_all_yields_no_base_and_no_java(self):
        df = parse("RUN echo hi\n")
        self.assertEqual(df.base_images, [])
        self.assertIsNone(df.final_base)
        self.assertIsNone(df.java_major)

    def test_package_manager_install_is_the_fallback_signal(self):
        # No recognisable Java base image, but the final stage apk-installs a
        # JDK: the version comes from the package name.
        df = parse("FROM alpine:3.19\nRUN apk add --no-cache openjdk17-jre\n")
        self.assertEqual(df.java_major, 17)


class TestEnvParsingEdges(unittest.TestCase):
    def test_unbalanced_quote_still_records_the_var(self):
        # shlex refuses the unterminated quote; the fallback split must keep
        # the assignment - dropping it would hide the JVM flags inside.
        df = parse('FROM openjdk:17\nENV JAVA_OPTS="-Xmx1g\n')
        self.assertIn("JAVA_OPTS", df.java_opts)
        self.assertIn("-Xmx1g", df.jvm_flags[0])

    def test_bare_token_in_kv_form_is_ignored(self):
        # 'ENV KEY=VAL stray' - the stray token has no '=' and is not a pair.
        df = parse("FROM openjdk:17\nENV JAVA_OPTS=-Xmx1g stray\n")
        self.assertEqual(df.java_opts, {"JAVA_OPTS": "-Xmx1g"})

    def test_legacy_env_with_key_only_yields_no_pair(self):
        df = parse("FROM openjdk:17\nENV JAVA_OPTS\n")
        self.assertEqual(df.java_opts, {})


class TestLauncherEdges(unittest.TestCase):
    def test_cmd_args_append_to_exec_entrypoint(self):
        # Docker semantics: exec-form ENTRYPOINT + CMD = one command line, so
        # a flag living in CMD is applied.
        df = parse('FROM openjdk:17\nENTRYPOINT ["java"]\n'
                   'CMD ["-Xmx256m", "-jar", "a.jar"]\n')
        self.assertIn("-Xmx256m", effective_flags(df))

    def test_no_launcher_counts_flags_but_calls_nothing_inert(self):
        # With neither ENTRYPOINT nor CMD the launch command is unknowable:
        # effective_flags is conservative (counts everything) and DF013's
        # input (inert_opt_vars) must be empty - "unknowable" is not "inert".
        df = parse('FROM openjdk:17\nENV JAVA_OPTS="-Xmx1g"\n')
        self.assertIn("-Xmx1g", effective_flags(df))
        self.assertEqual(inert_opt_vars(df), [])


class TestLogicalLineEdges(unittest.TestCase):
    def test_comment_inside_continuation_is_skipped(self):
        df = parse("FROM openjdk:17\n"
                   "RUN apt-get update \\\n"
                   "  # a comment inside the continuation\n"
                   "  && apt-get install -y curl\n"
                   "USER 10001\n")
        # the RUN stays one instruction and the following USER is still seen
        self.assertEqual([i["instr"] for i in df.instructions],
                         ["FROM", "RUN", "USER"])
        self.assertEqual(df.user, "10001")

    def test_trailing_continuation_at_eof_keeps_the_instruction(self):
        # final line ends in a continuation with nothing after it (no
        # trailing newline): the buffered instruction must still be emitted
        df = parse("FROM openjdk:17\nRUN echo hi \\")
        self.assertEqual([i["instr"] for i in df.instructions],
                         ["FROM", "RUN"])

    def test_bare_instruction_word_is_not_an_instruction(self):
        # a single word with no arguments matches no instruction grammar and
        # must be skipped, not crash or swallow the next line
        df = parse("FROM openjdk:17\nMAINTAINER\nUSER 10001\n")
        self.assertEqual(df.user, "10001")
        self.assertEqual([i["instr"] for i in df.instructions],
                         ["FROM", "USER"])

    def test_arg_without_default_contributes_no_substitution(self):
        df = parse("ARG VER\nFROM openjdk:17\n")
        self.assertEqual(df.java_major, 17)


if __name__ == "__main__":
    unittest.main()

import unittest

from hpaanalyzer.dockerparse import (effective_flags, extract_jvm_flags,
                                     inert_opt_vars, parse_dockerfile)


def parse(text):
    return parse_dockerfile("Dockerfile", text)


class TestBaseImage(unittest.TestCase):
    def test_java8_update(self):
        df = parse("FROM openjdk:8u151-jdk\n")
        self.assertEqual((df.java_major, df.java_update), (8, 151))
        self.assertEqual(df.java_flavor, "jdk")

    def test_temurin_dotted(self):
        df = parse("FROM eclipse-temurin:11.0.16_8-jre\n")
        self.assertEqual((df.java_major, df.java_update), (11, 16))

    def test_temurin_21(self):
        df = parse("FROM eclipse-temurin:21.0.3_9-jre\n")
        self.assertEqual(df.java_major, 21)

    def test_corretto_major_only(self):
        df = parse("FROM amazoncorretto:17\n")
        self.assertEqual((df.java_major, df.java_update), (17, None))

    def test_corporate_image_unknown(self):
        df = parse("FROM registry.corp.example/base/java-hardened:v3.2.1\n")
        self.assertIsNone(df.java_major)

    def test_arg_default_substitution(self):
        df = parse("ARG BASE=openjdk:8u181-jre\nFROM ${BASE}\n")
        self.assertEqual((df.java_major, df.java_update), (8, 181))

    def test_multistage_final_wins(self):
        df = parse("FROM eclipse-temurin:21-jdk AS build\n"
                   "FROM eclipse-temurin:21-jre\n")
        self.assertTrue(df.multistage)
        self.assertEqual(df.final_base["tag"], "21-jre")


class TestFlags(unittest.TestCase):
    def test_extract(self):
        flags = extract_jvm_flags("-Xmx512m -XX:+UseG1GC -Dfoo=bar java.jar")
        self.assertIn("-Xmx512m", flags)
        self.assertIn("-XX:+UseG1GC", flags)
        self.assertIn("-Dfoo=bar", flags)

    def test_env_java_opts_collected(self):
        df = parse('FROM openjdk:8\nENV JAVA_OPTS="-Xmx1g"\n')
        self.assertEqual(df.java_opts, {"JAVA_OPTS": "-Xmx1g"})
        self.assertIn("-Xmx1g", df.jvm_flags)


class TestEffectiveFlags(unittest.TestCase):
    def test_dead_java_opts_exec_form(self):
        df = parse('FROM openjdk:8\nENV JAVA_OPTS="-Xmx3g"\n'
                   'ENTRYPOINT ["java", "-jar", "app.jar"]\n')
        self.assertNotIn("-Xmx3g", effective_flags(df))
        self.assertEqual(inert_opt_vars(df), ["JAVA_OPTS"])

    def test_java_tool_options_always_applies(self):
        df = parse('FROM openjdk:8\nENV JAVA_TOOL_OPTIONS="-Xmx1g"\n'
                   'ENTRYPOINT ["java", "-jar", "app.jar"]\n')
        self.assertIn("-Xmx1g", effective_flags(df))
        self.assertEqual(inert_opt_vars(df), [])

    def test_shell_form_expands_everything(self):
        df = parse('FROM openjdk:8\nENV JAVA_OPTS="-Xmx1g"\n'
                   'ENTRYPOINT java $JAVA_OPTS -jar app.jar\n')
        self.assertIn("-Xmx1g", effective_flags(df))
        self.assertEqual(df.entrypoint["form"], "shell")

    def test_exec_form_referencing_var_via_sh(self):
        df = parse('FROM openjdk:8\nENV JAVA_OPTS="-Xmx1g"\n'
                   'ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]\n')
        self.assertIn("-Xmx1g", effective_flags(df))
        self.assertEqual(inert_opt_vars(df), [])

    def test_flags_in_entrypoint_itself(self):
        df = parse('FROM openjdk:8\n'
                   'ENTRYPOINT ["java", "-Xmx256m", "-jar", "app.jar"]\n')
        self.assertIn("-Xmx256m", effective_flags(df))


class TestInstructionFacts(unittest.TestCase):
    def test_user_and_healthcheck(self):
        df = parse("FROM openjdk:8\nUSER app\nHEALTHCHECK CMD true\n")
        self.assertEqual(df.user, "app")
        self.assertTrue(df.healthcheck)

    def test_line_continuation(self):
        df = parse('FROM openjdk:8\nENV JAVA_OPTS="-Xmx1g \\\n  -Xms1g"\n')
        self.assertIn("-Xms1g", df.jvm_flags)


if __name__ == "__main__":
    unittest.main()

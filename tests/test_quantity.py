import unittest

from hpaanalyzer.quantity import (fmt_bytes, fmt_millicores, is_decimal_mem,
                                  is_millibytes, parse_cpu, parse_jvm_size,
                                  parse_memory)


class TestCpu(unittest.TestCase):
    def test_millicores(self):
        self.assertEqual(parse_cpu("100m"), 100)
        self.assertEqual(parse_cpu("2"), 2000)
        self.assertEqual(parse_cpu("0.5"), 500)
        self.assertEqual(parse_cpu(1), 1000)

    def test_garbage(self):
        self.assertIsNone(parse_cpu("abc"))
        self.assertIsNone(parse_cpu(None))
        self.assertIsNone(parse_cpu(""))


class TestMemory(unittest.TestCase):
    def test_binary(self):
        self.assertEqual(parse_memory("512Mi"), 512 * 1024**2)
        self.assertEqual(parse_memory("1Gi"), 1024**3)
        self.assertEqual(parse_memory("2Ki"), 2048)

    def test_decimal(self):
        self.assertEqual(parse_memory("512M"), 512_000_000)
        self.assertEqual(parse_memory("1G"), 1_000_000_000)
        self.assertTrue(is_decimal_mem("512M"))
        self.assertFalse(is_decimal_mem("512Mi"))

    def test_millibytes_footgun(self):
        # '512m' is 0.512 BYTES - k8s-legal, virtually always a typo
        self.assertEqual(parse_memory("512m"), 0)
        self.assertTrue(is_millibytes("512m"))
        self.assertFalse(is_millibytes("512Mi"))
        self.assertFalse(is_millibytes(None))

    def test_bare_bytes(self):
        self.assertEqual(parse_memory("1048576"), 1048576)


class TestJvmSize(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(parse_jvm_size("512m"), 512 * 1024**2)  # JVM m == MiB!
        self.assertEqual(parse_jvm_size("3g"), 3 * 1024**3)
        self.assertEqual(parse_jvm_size("1024"), 1024)
        self.assertIsNone(parse_jvm_size("50%"))

    def test_jvm_vs_k8s_m_semantics_differ(self):
        # the same string means MiB to the JVM and millibytes to k8s
        self.assertNotEqual(parse_jvm_size("512m"), parse_memory("512m"))


class TestFmt(unittest.TestCase):
    def test_fmt(self):
        self.assertEqual(fmt_bytes(1024**3), "1 GiB")
        self.assertEqual(fmt_millicores(1500), "1500m")
        self.assertEqual(fmt_millicores(2000), "2 cores")
        self.assertEqual(fmt_bytes(None), "?")


if __name__ == "__main__":
    unittest.main()

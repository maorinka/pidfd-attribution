# SPDX-License-Identifier: GPL-2.0-only
"""The ring capacity is the shipped macro, not a measured rate."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CapacityDefaultTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_ring_bytes_come_from_the_shipped_header(self):
        sys.stderr.write(
            "capacity defaults are the shipped ring and segment sizes, not a measured rate\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "capacity-defaults"
            subprocess.run(
                [
                    "cc",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "shared/core"),
                    str(ROOT / "tests/capacity_defaults.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
                timeout=30,
            )
            output = subprocess.check_output([str(binary)], text=True, timeout=30)
        self.assertEqual(output, f"{8 * 1024 * 1024}\n")


if __name__ == "__main__":
    unittest.main()

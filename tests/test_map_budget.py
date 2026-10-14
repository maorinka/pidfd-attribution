# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the collector's actual checked map admission estimator."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MapBudgetTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_possible_cpu_storage_variants_and_overflow(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "map-budget"
            subprocess.run(
                [
                    "cc",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "endpoint-service/core"),
                    str(ROOT / "tests/map_budget.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
                timeout=30,
            )
            subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()

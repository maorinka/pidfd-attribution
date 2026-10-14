# SPDX-License-Identifier: GPL-2.0-only
"""Compile both shipped table-retirement hooks and call them."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SENTENCE = "table release keeps the zero close_files gate and the tracked kmem scan\n"


class TableReleaseGateTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_zero_count_and_tracked_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for have, endpoint in ((0, 0), (0, 1), (1, 0), (1, 1)):
                binary = directory / f"gate-{have}-{endpoint}"
                subprocess.run(
                    [
                        "cc",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        f"-DPIDFD_HAVE_CLOSE_FILES={have}",
                        f"-DPIDFD_ENDPOINT_POLICY={endpoint}",
                        "-I",
                        str(ROOT / "shared/core"),
                        str(ROOT / "tests/table_release_gate.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    timeout=30,
                )
                completed = subprocess.run(
                    [str(binary)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(completed.stdout, SENTENCE)
                sys.stderr.write(completed.stdout)


if __name__ == "__main__":
    unittest.main()

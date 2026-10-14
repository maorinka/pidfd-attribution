# SPDX-License-Identifier: GPL-2.0-only
"""Compile the shipped diagnostic increment and call it."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SENTENCE = "diagnostics increment looks up every call and retries after a miss\n"


class DiagnosticsIncrementTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_shipped_increment_retries_after_a_miss(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "diagnostics-increment"
            subprocess.run(
                [
                    "cc",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "shared/core"),
                    str(ROOT / "tests/diagnostics_increment.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
                timeout=30,
            )
            completed = subprocess.run(
                [str(binary)], check=True, capture_output=True, text=True, timeout=30
            )
        self.assertEqual(completed.stdout, SENTENCE)
        sys.stderr.write(completed.stdout)


if __name__ == "__main__":
    unittest.main()
